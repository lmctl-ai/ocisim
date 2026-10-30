package ai.lmctl.ocisim;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Immutable, process-local authentication and authorization configuration.
 * Key material and policy definitions stay in memory and never enter system properties or logs.
 */
public final class AuthConfig {

    public record JsonStatement(
            String effect,
            List<String> actions,
            List<String> resources,
            List<String> principals
    ) {}

    public record OciStatement(
            String effect,
            Set<String> groups,
            boolean anyUser,
            String verb,
            String resourceType,
            boolean inTenancy,
            String compartmentTarget,
            String whereBucketPattern,
            String whereActionPattern
    ) {}

    public record Credential(
            String keyId,
            String tenancyId,
            String userId,
            String fingerprint,
            PublicKey publicKey,
            Set<String> groups,
            boolean hasPolicy,
            List<JsonStatement> jsonStatements,
            List<OciStatement> ociStatements
    ) {}

    private static final Set<String> TOP_FIELDS = Set.of("credentials", "policies", "statements");
    private static final Set<String> CRED_FIELDS = Set.of(
            "keyId", "tenancy", "user", "fingerprint",
            "publicKeyPem", "publicKeyFile", "privateKeyPem", "privateKeyFile",
            "groups", "statements", "policy"
    );
    private static final Set<String> POLICY_FIELDS = Set.of("Version", "Statement");
    private static final Set<String> STATEMENT_FIELDS = Set.of(
            "Sid", "Effect", "Action", "ActionGlob", "Resource", "ResourceGlob", "Principal"
    );

    private static volatile AuthConfig current;

    private final Map<String, Credential> credentials;
    private final List<JsonStatement> globalJsonStatements;
    private final List<OciStatement> globalOciStatements;
    private final boolean hasGlobalPolicies;

    private AuthConfig(
            Map<String, Credential> credentials,
            List<JsonStatement> globalJsonStatements,
            List<OciStatement> globalOciStatements,
            boolean hasGlobalPolicies) {
        this.credentials = Map.copyOf(credentials);
        this.globalJsonStatements = List.copyOf(globalJsonStatements);
        this.globalOciStatements = List.copyOf(globalOciStatements);
        this.hasGlobalPolicies = hasGlobalPolicies;
    }

    public static AuthConfig current() {
        return current;
    }

    public Map<String, Credential> credentials() {
        return credentials;
    }

    public List<JsonStatement> globalJsonStatements() {
        return globalJsonStatements;
    }

    public List<OciStatement> globalOciStatements() {
        return globalOciStatements;
    }

    public boolean hasGlobalPolicies() {
        return hasGlobalPolicies;
    }

    static void configure(String mode, String file) {
        if (mode == null || !Set.of("open", "enforce").contains(mode)) {
            throw new IllegalArgumentException("auth must be open or enforce");
        }
        if ("open".equals(mode)) {
            if (file != null && !file.isBlank()) {
                parseFile(file);
            }
            current = null;
            return;
        }
        if (file == null || file.isBlank()) {
            throw new IllegalArgumentException("invalid or unreadable auth config");
        }
        current = parseFile(file);
    }

    private static AuthConfig parseFile(String file) {
        try {
            Path configPath = Path.of(file).toAbsolutePath().normalize();
            Path baseDir = configPath.getParent();
            JsonNode root = new ObjectMapper().readTree(configPath.toFile());
            if (!root.isObject()) {
                throw new IllegalArgumentException();
            }
            root.fieldNames().forEachRemaining(k -> {
                if (!TOP_FIELDS.contains(k)) {
                    throw new IllegalArgumentException();
                }
            });
            JsonNode credsNode = root.get("credentials");
            if (credsNode == null || !credsNode.isArray() || credsNode.isEmpty()) {
                throw new IllegalArgumentException();
            }

            List<JsonStatement> globalJson = new ArrayList<>();
            List<OciStatement> globalOci = new ArrayList<>();
            boolean hasGlobal = false;
            for (String field : List.of("policies", "statements")) {
                JsonNode node = root.get(field);
                if (node != null) {
                    hasGlobal = true;
                    parseMixedStatements(node, globalJson, globalOci);
                }
            }

            Map<String, Credential> credMap = new LinkedHashMap<>();
            for (JsonNode entry : credsNode) {
                if (!entry.isObject()) {
                    throw new IllegalArgumentException();
                }
                entry.fieldNames().forEachRemaining(k -> {
                    if (!CRED_FIELDS.contains(k)) {
                        throw new IllegalArgumentException();
                    }
                });
                String keyId = textOrNull(entry, "keyId");
                String tenancy = textOrNull(entry, "tenancy");
                String user = textOrNull(entry, "user");
                String fingerprint = textOrNull(entry, "fingerprint");
                if (keyId == null) {
                    if (tenancy == null || user == null || fingerprint == null) {
                        throw new IllegalArgumentException();
                    }
                    keyId = tenancy + "/" + user + "/" + fingerprint;
                }
                String[] parts = keyId.split("/");
                if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank() || parts[2].isBlank()) {
                    throw new IllegalArgumentException();
                }
                String resolvedTenancy = tenancy != null ? tenancy : parts[0];
                String resolvedUser = user != null ? user : parts[1];
                String resolvedFingerprint = fingerprint != null ? fingerprint : parts[2];

                PublicKey publicKey = resolvePublicKey(entry, baseDir);

                Set<String> groups = new LinkedHashSet<>();
                boolean hasPolicy = false;
                JsonNode groupsNode = entry.get("groups");
                if (groupsNode != null) {
                    if (!groupsNode.isArray()) {
                        throw new IllegalArgumentException();
                    }
                    for (JsonNode g : groupsNode) {
                        if (!g.isTextual() || g.asText().isBlank()) {
                            throw new IllegalArgumentException();
                        }
                        groups.add(g.asText().trim());
                    }
                }

                List<JsonStatement> credJson = new ArrayList<>();
                List<OciStatement> credOci = new ArrayList<>();

                JsonNode policyNode = entry.get("policy");
                if (policyNode != null) {
                    hasPolicy = true;
                    parsePolicyDocument(policyNode, credJson);
                }

                JsonNode stmtsNode = entry.get("statements");
                if (stmtsNode != null) {
                    hasPolicy = true;
                    parseMixedStatements(stmtsNode, credJson, credOci);
                }

                Credential cred = new Credential(
                        keyId,
                        resolvedTenancy,
                        resolvedUser,
                        resolvedFingerprint,
                        publicKey,
                        Set.copyOf(groups),
                        hasPolicy,
                        List.copyOf(credJson),
                        List.copyOf(credOci)
                );
                if (credMap.put(keyId, cred) != null) {
                    throw new IllegalArgumentException();
                }
            }
            return new AuthConfig(credMap, globalJson, globalOci, hasGlobal);
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid or unreadable auth config");
        }
    }

    private static void parsePolicyDocument(JsonNode policyNode, List<JsonStatement> out) {
        if (!policyNode.isObject() || !policyNode.path("Statement").isArray()) {
            throw new IllegalArgumentException();
        }
        policyNode.fieldNames().forEachRemaining(k -> {
            if (!POLICY_FIELDS.contains(k)) {
                throw new IllegalArgumentException();
            }
        });
        for (JsonNode stmt : policyNode.path("Statement")) {
            out.add(parseJsonStatement(stmt));
        }
    }

    private static void parseMixedStatements(
            JsonNode node,
            List<JsonStatement> jsonOut,
            List<OciStatement> ociOut) {
        if (!node.isArray()) {
            throw new IllegalArgumentException();
        }
        for (JsonNode item : node) {
            if (item.isTextual()) {
                ociOut.add(OciPolicyEngine.parseOciStatement(item.asText()));
            } else if (item.isObject()) {
                if (item.has("Statement")) {
                    parsePolicyDocument(item, jsonOut);
                } else {
                    jsonOut.add(parseJsonStatement(item));
                }
            } else {
                throw new IllegalArgumentException();
            }
        }
    }

    private static JsonStatement parseJsonStatement(JsonNode s) {
        if (!s.isObject()) {
            throw new IllegalArgumentException();
        }
        s.fieldNames().forEachRemaining(k -> {
            if (!STATEMENT_FIELDS.contains(k)) {
                throw new IllegalArgumentException();
            }
        });
        String effect = textOrNull(s, "Effect");
        if (effect == null || !Set.of("Allow", "Deny").contains(effect)) {
            throw new IllegalArgumentException();
        }
        JsonNode actionNode = s.has("Action") ? s.get("Action") : s.get("ActionGlob");
        JsonNode resourceNode = s.has("Resource") ? s.get("Resource") : s.get("ResourceGlob");
        List<String> actions = parseStringOrArray(actionNode, false);
        List<String> resources = parseStringOrArray(resourceNode, false);
        List<String> principals = s.has("Principal")
                ? parseStringOrArray(s.get("Principal"), false)
                : List.of("*");
        return new JsonStatement(effect, actions, resources, principals);
    }

    private static List<String> parseStringOrArray(JsonNode node, boolean allowEmpty) {
        if (node == null) {
            throw new IllegalArgumentException();
        }
        if (node.isTextual()) {
            String val = node.asText().trim();
            if (val.isEmpty()) {
                throw new IllegalArgumentException();
            }
            return List.of(val);
        }
        if (node.isArray()) {
            if (node.isEmpty() && !allowEmpty) {
                throw new IllegalArgumentException();
            }
            List<String> list = new ArrayList<>();
            for (JsonNode item : node) {
                if (!item.isTextual() || item.asText().isBlank()) {
                    throw new IllegalArgumentException();
                }
                list.add(item.asText().trim());
            }
            return List.copyOf(list);
        }
        throw new IllegalArgumentException();
    }

    private static PublicKey resolvePublicKey(JsonNode entry, Path baseDir) throws Exception {
        String pubPem = textOrNull(entry, "publicKeyPem");
        String pubFile = textOrNull(entry, "publicKeyFile");
        String privPem = textOrNull(entry, "privateKeyPem");
        String privFile = textOrNull(entry, "privateKeyFile");

        if (pubPem == null && pubFile != null) {
            Path p = Path.of(pubFile);
            if (!p.isAbsolute() && baseDir != null) {
                p = baseDir.resolve(p);
            }
            pubPem = Files.readString(p, StandardCharsets.UTF_8);
        }
        if (pubPem != null) {
            return parseRsaPublicKey(pubPem);
        }

        if (privPem == null && privFile != null) {
            Path p = Path.of(privFile);
            if (!p.isAbsolute() && baseDir != null) {
                p = baseDir.resolve(p);
            }
            privPem = Files.readString(p, StandardCharsets.UTF_8);
        }
        if (privPem != null) {
            return derivePublicKeyFromPrivatePem(privPem);
        }
        throw new IllegalArgumentException();
    }

    static PublicKey parseRsaPublicKey(String pem) throws Exception {
        String body = pem
                .replaceAll("-----BEGIN [A-Z0-9 ]*PUBLIC KEY-----", "")
                .replaceAll("-----END [A-Z0-9 ]*PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        if (body.isEmpty()) {
            throw new IllegalArgumentException();
        }
        byte[] der = Base64.getDecoder().decode(body);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new X509EncodedKeySpec(der));
    }

    static PublicKey derivePublicKeyFromPrivatePem(String pem) throws Exception {
        String body = pem
                .replaceAll("-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", "")
                .replaceAll("-----END [A-Z0-9 ]*PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        if (body.isEmpty()) {
            throw new IllegalArgumentException();
        }
        byte[] der = Base64.getDecoder().decode(body);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(der));
        if (priv instanceof RSAPrivateCrtKey crt) {
            return kf.generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
        }
        throw new IllegalArgumentException();
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode child = node.get(field);
        if (child == null || child.isNull()) {
            return null;
        }
        if (!child.isTextual()) {
            throw new IllegalArgumentException();
        }
        String text = child.asText().trim();
        if (text.isEmpty()) {
            throw new IllegalArgumentException();
        }
        return text;
    }
}
