package ai.lmctl.ocisim;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Evaluates OCI IAM policy statements and JSON policy statements against incoming HTTP requests.
 *
 * <p>Enforces:
 * <ul>
 *   <li>Default-deny when a policy set is attached to the principal or globally configured</li>
 *   <li>Explicit {@code Deny} overrides {@code Allow}</li>
 *   <li>Wildcard ({@code *}, {@code ?}) matching on actions, verbs, resource families, and resource identifiers</li>
 * </ul>
 */
public final class OciPolicyEngine {

    public enum Decision {
        ALLOW,
        DENY
    }

    public record Operation(
            String primaryAction,
            List<String> actionAliases,
            String verb,
            String resourceType,
            String resourceFamily,
            List<String> resources,
            String bucketName,
            String compartmentId
    ) {}

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Pattern OCI_STATEMENT_PATTERN = Pattern.compile(
            "(?i)^\\s*(allow|deny)\\s+"
                    + "(?:(any-user)|group\\s+([A-Za-z0-9_.,*?-]+))\\s+"
                    + "to\\s+([A-Za-z0-9_:*?-]+)\\s+"
                    + "([A-Za-z0-9_*?-]+)\\s+"
                    + "in\\s+(tenancy|compartment\\s+(?:id\\s+)?[A-Za-z0-9_.:*?-]+)"
                    + "(?:\\s+where\\s+(.+?))?\\s*$"
    );

    private static final Pattern WHERE_CLAUSE_PATTERN = Pattern.compile(
            "(?i)([a-z0-9_.]+)\\s*=\\s*['\"]([^'\"]+)['\"]"
    );

    private static final Map<String, Integer> VERB_RANKS = Map.of(
            "inspect", 1,
            "read", 2,
            "use", 3,
            "manage", 4
    );

    private OciPolicyEngine() {}

    public static AuthConfig.OciStatement parseOciStatement(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("empty OCI policy statement");
        }
        Matcher m = OCI_STATEMENT_PATTERN.matcher(raw.trim());
        if (!m.matches()) {
            throw new IllegalArgumentException("invalid OCI policy statement: " + raw);
        }
        String effect = m.group(1).equalsIgnoreCase("allow") ? "Allow" : "Deny";
        boolean anyUser = m.group(2) != null;
        Set<String> groups = new LinkedHashSet<>();
        if (!anyUser && m.group(3) != null) {
            for (String g : m.group(3).split(",")) {
                String trimmed = g.trim();
                if (!trimmed.isEmpty()) {
                    groups.add(trimmed);
                }
            }
            if (groups.isEmpty()) {
                throw new IllegalArgumentException("empty group in OCI statement");
            }
        }
        String verb = m.group(4).trim().toLowerCase(Locale.ROOT);
        String resourceType = m.group(5).trim().toLowerCase(Locale.ROOT);
        String scope = m.group(6).trim();
        boolean inTenancy = scope.equalsIgnoreCase("tenancy");
        String compartmentTarget = null;
        if (!inTenancy) {
            compartmentTarget = scope.replaceFirst("(?i)^compartment\\s+(?:id\\s+)?", "").trim();
        }
        String whereBucket = null;
        String whereAction = null;
        String whereRaw = m.group(7);
        if (whereRaw != null && !whereRaw.isBlank()) {
            Matcher wm = WHERE_CLAUSE_PATTERN.matcher(whereRaw);
            boolean matchedAny = false;
            while (wm.find()) {
                matchedAny = true;
                String key = wm.group(1).toLowerCase(Locale.ROOT);
                String val = wm.group(2);
                if (key.equals("target.bucket.name") || key.equals("target.resource.name")) {
                    whereBucket = val;
                } else if (key.equals("request.operation") || key.equals("request.permission") || key.equals("request.action")) {
                    whereAction = val;
                } else {
                    throw new IllegalArgumentException("unsupported where condition key: " + key);
                }
            }
            if (!matchedAny) {
                throw new IllegalArgumentException("invalid where clause: " + whereRaw);
            }
        }
        return new AuthConfig.OciStatement(
                effect,
                Set.copyOf(groups),
                anyUser,
                verb,
                resourceType,
                inTenancy,
                compartmentTarget,
                whereBucket,
                whereAction
        );
    }

    public static Decision evaluate(AuthConfig config, AuthConfig.Credential cred, Operation op) {
        if (op == null) {
            return Decision.DENY;
        }
        boolean hasAnyPolicy = cred.hasPolicy() || config.hasGlobalPolicies();
        if (!hasAnyPolicy) {
            return Decision.ALLOW;
        }

        boolean allowed = false;

        for (AuthConfig.JsonStatement stmt : cred.jsonStatements()) {
            if (matchesJsonStatement(stmt, cred, op, true)) {
                if ("Deny".equalsIgnoreCase(stmt.effect())) {
                    return Decision.DENY;
                }
                allowed = true;
            }
        }
        for (AuthConfig.JsonStatement stmt : config.globalJsonStatements()) {
            if (matchesJsonStatement(stmt, cred, op, false)) {
                if ("Deny".equalsIgnoreCase(stmt.effect())) {
                    return Decision.DENY;
                }
                allowed = true;
            }
        }
        for (AuthConfig.OciStatement stmt : cred.ociStatements()) {
            if (matchesOciStatement(stmt, cred, op, true)) {
                if ("Deny".equalsIgnoreCase(stmt.effect())) {
                    return Decision.DENY;
                }
                allowed = true;
            }
        }
        for (AuthConfig.OciStatement stmt : config.globalOciStatements()) {
            if (matchesOciStatement(stmt, cred, op, false)) {
                if ("Deny".equalsIgnoreCase(stmt.effect())) {
                    return Decision.DENY;
                }
                allowed = true;
            }
        }

        return allowed ? Decision.ALLOW : Decision.DENY;
    }

    private static boolean matchesJsonStatement(
            AuthConfig.JsonStatement stmt,
            AuthConfig.Credential cred,
            Operation op,
            boolean attachedToCred) {
        if (!attachedToCred && !matchesPrincipal(stmt.principals(), cred)) {
            return false;
        }
        boolean actionMatch = false;
        for (String pattern : stmt.actions()) {
            for (String candidate : op.actionAliases()) {
                if (globMatch(pattern, candidate, true)) {
                    actionMatch = true;
                    break;
                }
            }
            if (actionMatch) {
                break;
            }
        }
        if (!actionMatch) {
            return false;
        }
        for (String pattern : stmt.resources()) {
            for (String candidate : op.resources()) {
                if (globMatch(pattern, candidate, false)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean matchesPrincipal(List<String> principals, AuthConfig.Credential cred) {
        if (principals == null || principals.isEmpty()) {
            return true;
        }
        for (String p : principals) {
            if ("*".equals(p)
                    || globMatch(p, cred.keyId(), false)
                    || globMatch(p, cred.userId(), false)) {
                return true;
            }
            for (String g : cred.groups()) {
                if (globMatch(p, g, true) || globMatch(p, "group:" + g, true)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean matchesOciStatement(
            AuthConfig.OciStatement stmt,
            AuthConfig.Credential cred,
            Operation op,
            boolean attachedToCred) {
        if (!stmt.anyUser()) {
            boolean groupMatched = false;
            for (String stmtGroup : stmt.groups()) {
                if ("*".equals(stmtGroup)) {
                    groupMatched = true;
                    break;
                }
                for (String userGroup : cred.groups()) {
                    if (globMatch(stmtGroup, userGroup, true)) {
                        groupMatched = true;
                        break;
                    }
                }
                if (groupMatched) {
                    break;
                }
            }
            if (!groupMatched && !(attachedToCred && cred.groups().isEmpty())) {
                return false;
            }
        }

        if (!matchesOciResourceType(stmt.resourceType(), op)) {
            return false;
        }

        if (!matchesOciVerb(stmt.effect(), stmt.verb(), op)) {
            return false;
        }

        if (!stmt.inTenancy() && stmt.compartmentTarget() != null) {
            String target = stmt.compartmentTarget();
            String opComp = op.compartmentId() != null ? op.compartmentId() : cred.tenancyId();
            if (!globMatch(target, opComp, false)) {
                return false;
            }
        }

        if (stmt.whereBucketPattern() != null) {
            if (op.bucketName() == null || !globMatch(stmt.whereBucketPattern(), op.bucketName(), false)) {
                return false;
            }
        }

        if (stmt.whereActionPattern() != null) {
            boolean matched = false;
            for (String alias : op.actionAliases()) {
                if (globMatch(stmt.whereActionPattern(), alias, true)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                return false;
            }
        }

        return true;
    }

    private static boolean matchesOciResourceType(String pattern, Operation op) {
        if ("all-resources".equalsIgnoreCase(pattern) || "*".equals(pattern)) {
            return true;
        }
        if (globMatch(pattern, op.resourceType(), true)
                || globMatch(pattern, op.resourceFamily(), true)) {
            return true;
        }
        for (String res : op.resources()) {
            if (globMatch(pattern, res, false)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesOciVerb(String effect, String stmtVerb, Operation op) {
        Integer stmtRank = VERB_RANKS.get(stmtVerb.toLowerCase(Locale.ROOT));
        Integer opRank = VERB_RANKS.get(op.verb().toLowerCase(Locale.ROOT));
        if (stmtRank != null && opRank != null) {
            if ("Allow".equalsIgnoreCase(effect)) {
                return stmtRank >= opRank;
            } else {
                // In Deny statements:
                // - "Deny ... to manage" denies manage operations (opRank >= 4) while keeping read/inspect allowed
                // - "Deny ... to use" denies use and manage (opRank >= 3)
                // - "Deny ... to read" denies read, use, manage (opRank >= 2)
                // - "Deny ... to inspect" denies all operations (opRank >= 1)
                return opRank >= stmtRank;
            }
        }
        for (String candidate : op.actionAliases()) {
            if (globMatch(stmtVerb, candidate, true)) {
                return true;
            }
        }
        return globMatch(stmtVerb, op.verb(), true);
    }

    public static Operation resolveOperation(
            String method,
            String rawPath,
            String rawQuery,
            byte[] bodyBytes,
            String defaultTenancyId) {
        String m = method == null ? "GET" : method.toUpperCase(Locale.ROOT);
        String path = rawPath == null ? "/" : rawPath;
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        String trimmed = path.length() > 1 && path.endsWith("/")
                ? path.substring(0, path.length() - 1)
                : path;

        String queryCompartment = extractQueryParam(rawQuery, "compartmentId");
        JsonNode jsonBody = parseJsonBody(bodyBytes);
        String bodyCompartment = jsonField(jsonBody, "compartmentId");
        String compartmentId = firstNonNull(bodyCompartment, queryCompartment, defaultTenancyId);

        // 1. Object Storage (/n, /n/{ns}/...)
        if (trimmed.equals("/n") || trimmed.startsWith("/n/")) {
            return resolveObjectStorage(m, path, trimmed, jsonBody, compartmentId);
        }

        // 2. Identity (/20160918/...)
        if (trimmed.startsWith("/20160918/")) {
            return resolveIdentity(m, trimmed.substring("/20160918".length()), compartmentId);
        }

        // 3. Queue (/20210201/...)
        if (trimmed.startsWith("/20210201/")) {
            return resolveQueue(m, trimmed.substring("/20210201".length()), compartmentId);
        }

        // 4. Streaming (/20180418/...)
        if (trimmed.startsWith("/20180418/")) {
            return resolveStreaming(m, trimmed.substring("/20180418".length()), compartmentId);
        }

        // 5. KMS & Vault Secrets (/20180608/... and /20190301/...)
        if (trimmed.startsWith("/20180608/") || trimmed.startsWith("/20190301/")) {
            return resolveKmsAndVault(m, trimmed, compartmentId);
        }

        // 6. Functions (/20181201/...)
        if (trimmed.startsWith("/20181201/")) {
            return resolveFunctions(m, trimmed.substring("/20181201".length()), compartmentId);
        }

        // 7. OKE (/20180222/...)
        if (trimmed.startsWith("/20180222/")) {
            return resolveOke(m, trimmed.substring("/20180222".length()), compartmentId);
        }

        // 8. Generic workRequests (/workRequests...)
        if (trimmed.startsWith("/workRequests")) {
            return op("oci", "workrequests", "GetWorkRequest", "inspect", "work-requests", "all-resources",
                    List.of("workrequest:*", trimmed), null, compartmentId);
        }

        return null;
    }

    private static Operation resolveObjectStorage(
            String method,
            String rawPath,
            String trimmed,
            JsonNode jsonBody,
            String compartmentId) {
        if (trimmed.equals("/n")) {
            if ("GET".equals(method)) {
                return op("os", "objectstorage", "GetNamespace", "inspect", "namespaces", "object-family",
                        List.of("namespace:*", "*"), null, compartmentId);
            }
            return null;
        }
        String rest = rawPath.substring("/n/".length());
        int slash = rest.indexOf('/');
        if (slash < 0) {
            String ns = decode(rest);
            if ("GET".equals(method)) {
                return op("os", "objectstorage", "GetNamespaceMetadata", "inspect", "namespaces", "object-family",
                        List.of("namespace:" + ns, ns), null, compartmentId);
            }
            return null;
        }
        String ns = decode(rest.substring(0, slash));
        String afterNs = rest.substring(slash + 1);
        if (afterNs.equals("b") || afterNs.equals("b/")) {
            if ("POST".equals(method)) {
                String bucket = firstNonNull(jsonField(jsonBody, "name"), "*");
                return op("os", "objectstorage", "CreateBucket", "manage", "buckets", "object-family",
                        bucketResources(ns, bucket), bucket, compartmentId);
            }
            if ("GET".equals(method)) {
                return op("os", "objectstorage", "ListBuckets", "inspect", "buckets", "object-family",
                        bucketResources(ns, "*"), null, compartmentId);
            }
            return null;
        }
        if (!afterNs.startsWith("b/")) {
            return null;
        }
        String afterB = afterNs.substring(2);
        int bSlash = afterB.indexOf('/');
        if (bSlash < 0) {
            String bucket = decode(afterB);
            List<String> res = bucketResources(ns, bucket);
            return switch (method) {
                case "GET" -> op("os", "objectstorage", "GetBucket", "inspect", "buckets", "object-family", res, bucket, compartmentId);
                case "HEAD" -> op("os", "objectstorage", "HeadBucket", "inspect", "buckets", "object-family", res, bucket, compartmentId);
                case "POST" -> op("os", "objectstorage", "UpdateBucket", "manage", "buckets", "object-family", res, bucket, compartmentId);
                case "DELETE" -> op("os", "objectstorage", "DeleteBucket", "manage", "buckets", "object-family", res, bucket, compartmentId);
                default -> null;
            };
        }
        String bucket = decode(afterB.substring(0, bSlash));
        String afterBucket = afterB.substring(bSlash + 1);
        if (afterBucket.isEmpty()) {
            List<String> res = bucketResources(ns, bucket);
            return switch (method) {
                case "GET" -> op("os", "objectstorage", "GetBucket", "inspect", "buckets", "object-family", res, bucket, compartmentId);
                case "HEAD" -> op("os", "objectstorage", "HeadBucket", "inspect", "buckets", "object-family", res, bucket, compartmentId);
                case "POST" -> op("os", "objectstorage", "UpdateBucket", "manage", "buckets", "object-family", res, bucket, compartmentId);
                case "DELETE" -> op("os", "objectstorage", "DeleteBucket", "manage", "buckets", "object-family", res, bucket, compartmentId);
                default -> null;
            };
        }
        if (afterBucket.equals("o") || afterBucket.equals("o/")) {
            if ("GET".equals(method)) {
                return op("os", "objectstorage", "ListObjects", "inspect", "objects", "object-family",
                        objectResources(ns, bucket, "*"), bucket, compartmentId);
            }
            return null;
        }
        if (afterBucket.startsWith("o/")) {
            String objName = decode(afterBucket.substring(2));
            List<String> res = objectResources(ns, bucket, objName);
            return switch (method) {
                case "PUT" -> op("os", "objectstorage", "PutObject", "manage", "objects", "object-family", res, bucket, compartmentId);
                case "GET" -> op("os", "objectstorage", "GetObject", "read", "objects", "object-family", res, bucket, compartmentId);
                case "HEAD" -> op("os", "objectstorage", "HeadObject", "read", "objects", "object-family", res, bucket, compartmentId);
                case "DELETE" -> op("os", "objectstorage", "DeleteObject", "manage", "objects", "object-family", res, bucket, compartmentId);
                default -> null;
            };
        }
        if (afterBucket.startsWith("actions/")) {
            String action = afterBucket.substring("actions/".length());
            String opName = Character.toUpperCase(action.charAt(0)) + action.substring(1);
            String obj = firstNonNull(jsonField(jsonBody, "sourceName"), jsonField(jsonBody, "newName"), "*");
            return op("os", "objectstorage", opName, "manage", "objects", "object-family",
                    objectResources(ns, bucket, obj), bucket, compartmentId);
        }
        if (afterBucket.equals("u") || afterBucket.startsWith("u/")) {
            String obj = afterBucket.length() > 2 ? decode(afterBucket.substring(2)) : "*";
            String verb = "GET".equals(method) ? "inspect" : "use";
            String opName = switch (method) {
                case "GET" -> "ListMultipartUploads";
                case "POST" -> "CreateMultipartUpload";
                case "PUT" -> "UploadPart";
                case "DELETE" -> "AbortMultipartUpload";
                default -> "MultipartUpload";
            };
            return op("os", "objectstorage", opName, verb, "objects", "object-family",
                    objectResources(ns, bucket, obj), bucket, compartmentId);
        }
        if (afterBucket.equals("p") || afterBucket.startsWith("p/")) {
            String verb = "GET".equals(method) ? "inspect" : "manage";
            String opName = switch (method) {
                case "POST" -> "CreatePreauthenticatedRequest";
                case "GET" -> afterBucket.length() > 2 ? "GetPreauthenticatedRequest" : "ListPreauthenticatedRequests";
                case "DELETE" -> "DeletePreauthenticatedRequest";
                default -> "PreauthenticatedRequest";
            };
            return op("os", "objectstorage", opName, verb, "preauthenticated-requests", "object-family",
                    bucketResources(ns, bucket), bucket, compartmentId);
        }
        if (afterBucket.startsWith("retentionRules")) {
            String verb = "GET".equals(method) ? "inspect" : "manage";
            return op("os", "objectstorage", "RetentionRule", verb, "buckets", "object-family",
                    bucketResources(ns, bucket), bucket, compartmentId);
        }
        return null;
    }

    private static Operation resolveIdentity(String method, String subPath, String compartmentId) {
        if (subPath.startsWith("/tenancies")) {
            String verb = "GET".equals(method) ? "inspect" : "manage";
            String action = subPath.contains("/regionSubscriptions") ? "ListRegionSubscriptions" : "GetTenancy";
            return op("iam", "identity", action, verb, "tenancies", "iam-family",
                    List.of("tenancy:" + compartmentId, compartmentId, "*"), null, compartmentId);
        }
        if (subPath.equals("/compartments") || subPath.startsWith("/compartments/")) {
            boolean isCollection = subPath.equals("/compartments");
            String action = switch (method) {
                case "GET" -> isCollection ? "ListCompartments" : "GetCompartment";
                case "POST" -> subPath.endsWith("/moveCompartment") ? "MoveCompartment"
                        : subPath.endsWith("/recoverCompartment") ? "RecoverCompartment" : "CreateCompartment";
                case "PUT" -> "UpdateCompartment";
                case "DELETE" -> "DeleteCompartment";
                default -> "Compartment";
            };
            String verb = "GET".equals(method) ? "inspect" : "manage";
            return op("iam", "identity", action, verb, "compartments", "iam-family",
                    List.of("compartment:" + compartmentId, compartmentId, "compartment:*"), null, compartmentId);
        }
        if (subPath.equals("/users") || subPath.startsWith("/users/")) {
            boolean isCollection = subPath.equals("/users");
            String action = switch (method) {
                case "GET" -> isCollection ? "ListUsers" : "GetUser";
                case "POST" -> "CreateUser";
                case "PUT" -> "UpdateUser";
                case "DELETE" -> "DeleteUser";
                default -> "User";
            };
            String verb = "GET".equals(method) ? "inspect" : "manage";
            return op("iam", "identity", action, verb, "users", "iam-family",
                    List.of("user:*", compartmentId), null, compartmentId);
        }
        if (subPath.equals("/groups") || subPath.startsWith("/groups/")) {
            boolean isCollection = subPath.equals("/groups");
            String action = switch (method) {
                case "GET" -> isCollection ? "ListGroups" : "GetGroup";
                case "POST" -> "CreateGroup";
                case "PUT" -> "UpdateGroup";
                case "DELETE" -> "DeleteGroup";
                default -> "Group";
            };
            String verb = "GET".equals(method) ? "inspect" : "manage";
            return op("iam", "identity", action, verb, "groups", "iam-family",
                    List.of("group:*", compartmentId), null, compartmentId);
        }
        if (subPath.equals("/userGroupMemberships") || subPath.startsWith("/userGroupMemberships/")) {
            boolean isCollection = subPath.equals("/userGroupMemberships");
            String action = switch (method) {
                case "GET" -> isCollection ? "ListUserGroupMemberships" : "GetUserGroupMembership";
                case "POST" -> "AddUserToGroup";
                case "DELETE" -> "RemoveUserFromGroup";
                default -> "UserGroupMembership";
            };
            String verb = "GET".equals(method) ? "inspect" : "manage";
            return op("iam", "identity", action, verb, "groups", "iam-family",
                    List.of("group:*", compartmentId), null, compartmentId);
        }
        if (subPath.equals("/policies") || subPath.startsWith("/policies/")) {
            boolean isCollection = subPath.equals("/policies");
            String action = switch (method) {
                case "GET" -> isCollection ? "ListPolicies" : "GetPolicy";
                case "POST" -> "CreatePolicy";
                case "PUT" -> "UpdatePolicy";
                case "DELETE" -> "DeletePolicy";
                default -> "Policy";
            };
            String verb = "GET".equals(method) ? "inspect" : "manage";
            return op("iam", "identity", action, verb, "policies", "iam-family",
                    List.of("policy:*", compartmentId), null, compartmentId);
        }
        if (subPath.startsWith("/availabilityDomains")) {
            return op("iam", "identity", "ListAvailabilityDomains", "inspect", "compartments", "iam-family",
                    List.of("compartment:" + compartmentId, "*"), null, compartmentId);
        }
        if (subPath.startsWith("/faultDomains")) {
            return op("iam", "identity", "ListFaultDomains", "inspect", "compartments", "iam-family",
                    List.of("compartment:" + compartmentId, "*"), null, compartmentId);
        }
        if (subPath.startsWith("/regions")) {
            return op("iam", "identity", "ListRegions", "inspect", "tenancies", "iam-family",
                    List.of("tenancy:" + compartmentId, "*"), null, compartmentId);
        }
        if (subPath.startsWith("/workRequests") || subPath.startsWith("/iamWorkRequests")) {
            return op("iam", "identity", "GetWorkRequest", "inspect", "compartments", "iam-family",
                    List.of("workrequest:*", "*"), null, compartmentId);
        }
        return op("iam", "identity", "IdentityOperation", "GET".equals(method) ? "inspect" : "manage",
                "compartments", "iam-family", List.of("compartment:" + compartmentId, "*"), null, compartmentId);
    }

    private static Operation resolveQueue(String method, String subPath, String compartmentId) {
        if (subPath.equals("/queues")) {
            if ("POST".equals(method)) {
                return op("queue", "queue", "CreateQueue", "manage", "queues", "queue-family",
                        List.of("queue:*", compartmentId), null, compartmentId);
            }
            if ("GET".equals(method)) {
                return op("queue", "queue", "ListQueues", "inspect", "queues", "queue-family",
                        List.of("queue:*", compartmentId), null, compartmentId);
            }
        }
        if (subPath.startsWith("/queues/")) {
            String rest = subPath.substring("/queues/".length());
            int slash = rest.indexOf('/');
            String queueId = slash < 0 ? decode(rest) : decode(rest.substring(0, slash));
            List<String> res = List.of("queue:" + queueId, queueId, "queue:*");
            if (slash < 0) {
                return switch (method) {
                    case "GET" -> op("queue", "queue", "GetQueue", "read", "queues", "queue-family", res, null, compartmentId);
                    case "PUT" -> op("queue", "queue", "UpdateQueue", "manage", "queues", "queue-family", res, null, compartmentId);
                    case "DELETE" -> op("queue", "queue", "DeleteQueue", "manage", "queues", "queue-family", res, null, compartmentId);
                    default -> null;
                };
            }
            String afterQueue = rest.substring(slash + 1);
            if (afterQueue.equals("messages") || afterQueue.startsWith("messages/")) {
                String action = switch (method) {
                    case "POST" -> afterQueue.endsWith("deleteMessages") ? "DeleteMessages"
                            : afterQueue.endsWith("updateMessages") ? "UpdateMessages" : "PutMessages";
                    case "GET" -> "GetMessages";
                    case "DELETE" -> "DeleteMessage";
                    case "PUT" -> "UpdateMessage";
                    default -> "QueueMessages";
                };
                String verb = "GET".equals(method) ? "read" : "use";
                return op("queue", "queue", action, verb, "queues", "queue-family", res, null, compartmentId);
            }
            if (afterQueue.equals("stats") || afterQueue.equals("channels")) {
                return op("queue", "queue", "GetStats", "read", "queues", "queue-family", res, null, compartmentId);
            }
            return op("queue", "queue", "UpdateQueue", "manage", "queues", "queue-family", res, null, compartmentId);
        }
        if (subPath.startsWith("/workRequests")) {
            return op("queue", "queue", "GetWorkRequest", "inspect", "queues", "queue-family",
                    List.of("workrequest:*", "queue:*"), null, compartmentId);
        }
        return null;
    }

    private static Operation resolveStreaming(String method, String subPath, String compartmentId) {
        if (subPath.equals("/streams")) {
            if ("POST".equals(method)) {
                return op("streaming", "streaming", "CreateStream", "manage", "streams", "stream-family",
                        List.of("stream:*", compartmentId), null, compartmentId);
            }
            if ("GET".equals(method)) {
                return op("streaming", "streaming", "ListStreams", "inspect", "streams", "stream-family",
                        List.of("stream:*", compartmentId), null, compartmentId);
            }
        }
        if (subPath.startsWith("/streams/")) {
            String rest = subPath.substring("/streams/".length());
            int slash = rest.indexOf('/');
            String streamId = slash < 0 ? decode(rest) : decode(rest.substring(0, slash));
            List<String> res = List.of("stream:" + streamId, streamId, "stream:*");
            if (slash < 0) {
                return switch (method) {
                    case "GET" -> op("streaming", "streaming", "GetStream", "read", "streams", "stream-family", res, null, compartmentId);
                    case "PUT", "POST" -> op("streaming", "streaming", "UpdateStream", "manage", "streams", "stream-family", res, null, compartmentId);
                    case "DELETE" -> op("streaming", "streaming", "DeleteStream", "manage", "streams", "stream-family", res, null, compartmentId);
                    default -> null;
                };
            }
            String after = rest.substring(slash + 1);
            if (after.equals("messages")) {
                if ("POST".equals(method)) {
                    return op("streaming", "streaming", "PutMessages", "use", "streams", "stream-family", res, null, compartmentId);
                }
                if ("GET".equals(method)) {
                    return op("streaming", "streaming", "GetMessages", "read", "streams", "stream-family", res, null, compartmentId);
                }
            }
            if (after.equals("cursors") || after.equals("groupCursors")) {
                return op("streaming", "streaming", "CreateCursor", "read", "streams", "stream-family", res, null, compartmentId);
            }
            return op("streaming", "streaming", "StreamData", "use", "streams", "stream-family", res, null, compartmentId);
        }
        if (subPath.startsWith("/workRequests")) {
            return op("streaming", "streaming", "GetWorkRequest", "inspect", "streams", "stream-family",
                    List.of("workrequest:*", "stream:*"), null, compartmentId);
        }
        return null;
    }

    private static Operation resolveKmsAndVault(String method, String trimmed, String compartmentId) {
        if (trimmed.startsWith("/20190301/secretbundles")) {
            return op("secrets", "vault", "GetSecretBundle", "read", "secret-bundles", "secret-family",
                    List.of("secret:*", compartmentId), null, compartmentId);
        }
        String sub = trimmed.substring("/20180608".length());
        if (sub.startsWith("/secrets")) {
            boolean isColl = sub.equals("/secrets");
            String action = switch (method) {
                case "GET" -> isColl ? "ListSecrets" : "GetSecret";
                case "POST" -> isColl ? "CreateSecret" : "UpdateSecret";
                case "PUT" -> "UpdateSecret";
                default -> "Secret";
            };
            String verb = "GET".equals(method) ? (isColl ? "inspect" : "read") : "manage";
            return op("vault", "secrets", action, verb, "secrets", "secret-family",
                    List.of("secret:*", compartmentId), null, compartmentId);
        }
        if (sub.startsWith("/vaults")) {
            boolean isColl = sub.equals("/vaults");
            String action = switch (method) {
                case "GET" -> isColl ? "ListVaults" : "GetVault";
                case "POST" -> isColl ? "CreateVault" : "UpdateVault";
                case "PUT" -> "UpdateVault";
                default -> "Vault";
            };
            String verb = "GET".equals(method) ? (isColl ? "inspect" : "read") : "manage";
            return op("kms", "keymanagement", action, verb, "vaults", "vault-family",
                    List.of("vault:*", compartmentId), null, compartmentId);
        }
        if (sub.startsWith("/keys")) {
            boolean isColl = sub.equals("/keys");
            String action = switch (method) {
                case "GET" -> isColl ? "ListKeys" : "GetKey";
                case "POST" -> isColl ? "CreateKey" : "UpdateKey";
                case "PUT" -> "UpdateKey";
                default -> "Key";
            };
            String verb = "GET".equals(method) ? (isColl ? "inspect" : "read") : "manage";
            return op("kms", "keymanagement", action, verb, "keys", "vault-family",
                    List.of("key:*", compartmentId), null, compartmentId);
        }
        String cryptoOp = sub.startsWith("/") ? sub.substring(1) : sub;
        String cap = cryptoOp.isEmpty() ? "Crypto" : Character.toUpperCase(cryptoOp.charAt(0)) + cryptoOp.substring(1);
        return op("kms", "keymanagement", cap, "use", "keys", "vault-family",
                List.of("key:*", compartmentId), null, compartmentId);
    }

    private static Operation resolveFunctions(String method, String subPath, String compartmentId) {
        if (subPath.endsWith("/actions/invoke")) {
            return op("fn", "functions", "InvokeFunction", "use", "fn-invocation", "fn-family",
                    List.of("function:*", compartmentId), null, compartmentId);
        }
        if (subPath.startsWith("/applications")) {
            boolean isColl = subPath.equals("/applications");
            String action = switch (method) {
                case "GET" -> isColl ? "ListApplications" : "GetApplication";
                case "POST" -> "CreateApplication";
                case "PUT" -> "UpdateApplication";
                case "DELETE" -> "DeleteApplication";
                default -> "Application";
            };
            String verb = "GET".equals(method) ? (isColl ? "inspect" : "read") : "manage";
            return op("fn", "functions", action, verb, "fn-app", "fn-family",
                    List.of("application:*", compartmentId), null, compartmentId);
        }
        if (subPath.startsWith("/functions")) {
            boolean isColl = subPath.equals("/functions");
            String action = switch (method) {
                case "GET" -> isColl ? "ListFunctions" : "GetFunction";
                case "POST" -> "CreateFunction";
                case "PUT" -> "UpdateFunction";
                case "DELETE" -> "DeleteFunction";
                default -> "Function";
            };
            String verb = "GET".equals(method) ? (isColl ? "inspect" : "read") : "manage";
            return op("fn", "functions", action, verb, "fn-function", "fn-family",
                    List.of("function:*", compartmentId), null, compartmentId);
        }
        return null;
    }

    private static Operation resolveOke(String method, String subPath, String compartmentId) {
        String verb = "GET".equals(method) ? "inspect" : "manage";
        String action = subPath.startsWith("/clusters")
                ? ("GET".equals(method) ? (subPath.equals("/clusters") ? "ListClusters" : "GetCluster") : "ManageCluster")
                : "OkeOperation";
        return op("oke", "containerengine", action, verb, "clusters", "cluster-family",
                List.of("cluster:*", compartmentId), null, compartmentId);
    }

    private static Operation op(
            String shortService,
            String longService,
            String actionName,
            String verb,
            String resourceType,
            String resourceFamily,
            List<String> resources,
            String bucketName,
            String compartmentId) {
        String primary = "oci:" + shortService + ":" + actionName;
        Set<String> aliases = new LinkedHashSet<>();
        aliases.add(primary);
        aliases.add("oci:" + longService + ":" + actionName);
        aliases.add(shortService + ":" + actionName);
        aliases.add(longService + ":" + actionName);
        aliases.add(actionName);
        return new Operation(
                primary,
                List.copyOf(aliases),
                verb,
                resourceType,
                resourceFamily,
                resources,
                bucketName,
                compartmentId
        );
    }

    private static List<String> bucketResources(String ns, String bucket) {
        List<String> list = new ArrayList<>();
        list.add("bucket:" + bucket);
        list.add("oci:os:" + ns + ":bucket:" + bucket);
        list.add(ns + "/" + bucket);
        list.add(bucket);
        return List.copyOf(list);
    }

    private static List<String> objectResources(String ns, String bucket, String objectName) {
        List<String> list = new ArrayList<>();
        list.add("bucket:" + bucket + "/object:" + objectName);
        list.add("oci:os:" + ns + ":bucket:" + bucket + "/object:" + objectName);
        list.add(ns + "/" + bucket + "/" + objectName);
        list.add(bucket + "/" + objectName);
        list.add("object:" + objectName);
        return List.copyOf(list);
    }

    public static boolean globMatch(String pattern, String value, boolean caseInsensitive) {
        if (pattern == null || value == null) {
            return false;
        }
        String p = caseInsensitive ? pattern.toLowerCase(Locale.ROOT) : pattern;
        String v = caseInsensitive ? value.toLowerCase(Locale.ROOT) : value;
        if ("*".equals(p) || "**".equals(p) || p.equals(v)) {
            return true;
        }
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < p.length(); i++) {
            char c = p.charAt(i);
            switch (c) {
                case '*' -> {
                    if (i + 1 < p.length() && p.charAt(i + 1) == '*') {
                        regex.append(".*");
                        i++;
                    } else {
                        regex.append("[^/]*");
                    }
                }
                case '?' -> regex.append("[^/]");
                case '.', '(', ')', '+', '|', '^', '$', '@', '%', '[', ']', '{', '}', '\\' ->
                        regex.append('\\').append(c);
                default -> regex.append(c);
            }
        }
        regex.append('$');
        return Pattern.compile(regex.toString(), Pattern.DOTALL).matcher(v).matches();
    }

    private static String extractQueryParam(String rawQuery, String paramName) {
        if (rawQuery == null || rawQuery.isEmpty()) {
            return null;
        }
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            String key = eq >= 0 ? pair.substring(0, eq) : pair;
            if (paramName.equals(decode(key))) {
                return eq >= 0 ? decode(pair.substring(eq + 1)) : "";
            }
        }
        return null;
    }

    private static JsonNode parseJsonBody(byte[] bodyBytes) {
        if (bodyBytes == null || bodyBytes.length == 0 || bodyBytes.length > 1024 * 1024) {
            return null;
        }
        byte first = 0;
        for (byte b : bodyBytes) {
            if (!Character.isWhitespace(b)) {
                first = b;
                break;
            }
        }
        if (first != '{') {
            return null;
        }
        try {
            return MAPPER.readTree(bodyBytes);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String jsonField(JsonNode node, String field) {
        if (node == null || !node.isObject()) {
            return null;
        }
        JsonNode child = node.get(field);
        if (child != null && child.isTextual() && !child.asText().isBlank()) {
            return child.asText().trim();
        }
        return null;
    }

    private static String decode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }

    private static String firstNonNull(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }
}
