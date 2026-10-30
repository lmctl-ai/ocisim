package ai.lmctl.ocisim;

import io.floci.oci.core.auth.OciSignatureParser;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Enforces OCI HTTP Signature authentication (Layer 1) and IAM policy permissions (Layer 2)
 * when {@code --auth enforce} is active.
 */
@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION + 1)
public class OciAuthFilter implements ContainerRequestFilter {

    private static final int MAX_BODY_BYTES = 32 * 1024 * 1024;
    private static final String NOT_AUTHENTICATED_MSG =
            "The required information to complete authentication was not provided or was incorrect.";
    private static final String NOT_AUTHORIZED_MSG =
            "Authorization failed or requested resource not found.";
    private static final String OCI_ERROR_TEMPLATE = """
            {
              "code": ${code},
              "message": ${message}
            }
            """;

    @Override
    public void filter(ContainerRequestContext ctx) {
        AuthConfig config = AuthConfig.current();
        if (config == null) {
            return;
        }

        String path = ctx.getUriInfo().getPath();
        String normPath = path.startsWith("/") ? path.substring(1) : path;
        if (normPath.equals("health") || normPath.startsWith("_floci-oci") || normPath.startsWith("p/")) {
            return;
        }

        byte[] bodyBytes = new byte[0];
        String method = ctx.getMethod().toUpperCase(Locale.ROOT);
        if (ctx.hasEntity() || "POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            try {
                InputStream in = ctx.getEntityStream();
                if (in != null) {
                    bodyBytes = in.readNBytes(MAX_BODY_BYTES + 1);
                    if (bodyBytes.length > MAX_BODY_BYTES) {
                        rejectNotAuthenticated(ctx);
                        return;
                    }
                    ctx.setEntityStream(new ByteArrayInputStream(bodyBytes));
                }
            } catch (Exception e) {
                rejectNotAuthenticated(ctx);
                return;
            }
        }

        AuthConfig.Credential cred = verifySignature(ctx, config, bodyBytes);
        if (cred == null) {
            rejectNotAuthenticated(ctx);
            return;
        }

        URI reqUri = ctx.getUriInfo().getRequestUri();
        OciPolicyEngine.Operation op = OciPolicyEngine.resolveOperation(
                ctx.getMethod(),
                reqUri.getRawPath(),
                reqUri.getRawQuery(),
                bodyBytes,
                cred.tenancyId()
        );
        if (OciPolicyEngine.evaluate(config, cred, op) != OciPolicyEngine.Decision.ALLOW) {
            rejectNotAuthorized(ctx);
        }
    }

    private static AuthConfig.Credential verifySignature(
            ContainerRequestContext ctx,
            AuthConfig config,
            byte[] bodyBytes) {
        try {
            String authHeader = ctx.getHeaderString(HttpHeaders.AUTHORIZATION);
            if (!OciSignatureParser.isSignatureScheme(authHeader)) {
                return null;
            }
            Map<String, String> params = OciSignatureParser.parameters(authHeader);
            String version = params.get("version");
            String algorithm = params.get("algorithm");
            String keyId = params.get("keyid");
            String headersParam = params.get("headers");
            String signatureB64 = params.get("signature");

            if (!"1".equals(version)
                    || algorithm == null || !"rsa-sha256".equalsIgnoreCase(algorithm)
                    || keyId == null || keyId.isBlank()
                    || headersParam == null || headersParam.isBlank()
                    || signatureB64 == null || signatureB64.isBlank()) {
                return null;
            }

            AuthConfig.Credential cred = config.credentials().get(keyId);
            if (cred == null) {
                return null;
            }

            String[] signedHeaders = headersParam.trim().split("\\s+");
            Set<String> seen = new HashSet<>();
            for (String h : signedHeaders) {
                String lower = h.toLowerCase(Locale.ROOT);
                if (!seen.add(lower)) {
                    return null;
                }
            }
            if (!seen.contains("(request-target)")
                    || !seen.contains("host")
                    || (!seen.contains("date") && !seen.contains("x-date"))) {
                return null;
            }

            String contentShaHeader = ctx.getHeaderString("x-content-sha256");
            if (seen.contains("x-content-sha256") || contentShaHeader != null) {
                if (contentShaHeader == null) {
                    return null;
                }
                String actualSha = sha256Base64(bodyBytes);
                if (!MessageDigest.isEqual(
                        actualSha.getBytes(StandardCharsets.UTF_8),
                        contentShaHeader.trim().getBytes(StandardCharsets.UTF_8))) {
                    return null;
                }
            }

            URI reqUri = ctx.getUriInfo().getRequestUri();
            String rawPath = reqUri.getRawPath();
            if (rawPath == null || rawPath.isEmpty()) {
                rawPath = "/";
            }
            String rawQuery = reqUri.getRawQuery();
            String requestTarget = (rawQuery == null || rawQuery.isEmpty())
                    ? rawPath
                    : rawPath + "?" + rawQuery;

            StringBuilder signingString = new StringBuilder();
            for (int i = 0; i < signedHeaders.length; i++) {
                if (i > 0) {
                    signingString.append('\n');
                }
                String h = signedHeaders[i].toLowerCase(Locale.ROOT);
                if ("(request-target)".equals(h)) {
                    signingString.append("(request-target): ")
                            .append(ctx.getMethod().toLowerCase(Locale.ROOT))
                            .append(' ')
                            .append(requestTarget);
                } else {
                    String val = ctx.getHeaderString(h);
                    if (val == null && "content-length".equals(h) && bodyBytes.length == 0) {
                        val = "0";
                    }
                    if (val == null) {
                        return null;
                    }
                    signingString.append(h).append(": ").append(val);
                }
            }

            byte[] sigBytes = Base64.getDecoder().decode(signatureB64.trim());
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(cred.publicKey());
            verifier.update(signingString.toString().getBytes(StandardCharsets.UTF_8));
            if (!verifier.verify(sigBytes)) {
                return null;
            }
            return cred;
        } catch (Exception e) {
            return null;
        }
    }

    private static String sha256Base64(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(data));
    }

    private static void rejectNotAuthenticated(ContainerRequestContext ctx) {
        reject(ctx, 401, "NotAuthenticated", NOT_AUTHENTICATED_MSG);
    }

    private static void rejectNotAuthorized(ContainerRequestContext ctx) {
        reject(ctx, 403, "NotAuthorizedOrNotFound", NOT_AUTHORIZED_MSG);
    }

    private static void reject(ContainerRequestContext ctx, int status, String code, String message) {
        String body = Main.renderJsonTemplate(OCI_ERROR_TEMPLATE, Map.of("code", code, "message", message));
        ctx.abortWith(Response.status(status)
                .type(MediaType.APPLICATION_JSON)
                .entity(body)
                .build());
    }
}
