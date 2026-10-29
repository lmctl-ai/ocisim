package ai.lmctl.ocisim;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.annotations.QuarkusMain;

import java.nio.file.Files;
import java.nio.file.Path;

/** The only overlay on upstream: argument handling before Quarkus starts. */
@QuarkusMain
public final class Main {
    private Main() {}

    public static void main(String[] args) {
        if (args.length == 1 && args[0].equals("--version")) {
            System.out.println("ocisim @VERSION@ (floci-oci @UPSTREAM@)");
            return;
        }
        if (args.length == 1 && (args[0].equals("--help") || args[0].equals("-h"))) {
            System.out.println("""
                ocisim: local OCI emulator, powered by floci-oci
                Usage: ocisim serve|start [--port 4599] [--data-dir PATH]
                       ocisim --version | --help
                Listens on 127.0.0.1. Foreground; Ctrl-C stops the server.
                Default storage is memory. --data-dir enables persistent storage.
                Health: http://127.0.0.1:4599/_floci-oci/health
                Default tenancy: ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000
                Default namespace: floci-local; region: us-ashburn-1
                """);
            return;
        }
        try {
            configure(args);
        } catch (IllegalArgumentException e) {
            failure("usage", e.getMessage(), 2);
            return;
        }
        try {
            Quarkus.run(null, (code, error) -> {
                if (code != 0 || error != null) {
                    failure("runtime", "emulator failed; see stderr", 3);
                }
            }, args);
        } catch (Throwable error) {
            failure("runtime", "emulator failed; see stderr", 3);
        }
    }

    static void configure(String[] args) {
        if (args.length == 0 || !(args[0].equals("serve") || args[0].equals("start"))) {
            throw new IllegalArgumentException("expected serve or start; use --help");
        }
        int port = 4599;
        String directory = null;
        boolean portSeen = false;
        for (int i = 1; i < args.length; i++) {
            String option = args[i];
            if (++i == args.length) {
                throw new IllegalArgumentException("missing option value");
            }
            switch (option) {
                case "--port" -> {
                    if (portSeen) {
                        throw new IllegalArgumentException("duplicate --port");
                    }
                    portSeen = true;
                    try {
                        port = Integer.parseInt(args[i]);
                    } catch (NumberFormatException e) {
                        throw new IllegalArgumentException("port must be an integer from 1 to 65535");
                    }
                    if (port < 1 || port > 65535) {
                        throw new IllegalArgumentException("port must be an integer from 1 to 65535");
                    }
                }
                case "--data-dir" -> {
                    if (directory != null || args[i].isBlank()) {
                        throw new IllegalArgumentException("--data-dir requires one nonempty path");
                    }
                    directory = Path.of(args[i]).toAbsolutePath().normalize().toString();
                }
                default -> throw new IllegalArgumentException("unknown option; use --help");
            }
        }
        System.setProperty("quarkus.http.host", "127.0.0.1");
        System.setProperty("quarkus.http.port", Integer.toString(port));
        System.setProperty("floci-oci.port", Integer.toString(port));
        System.setProperty("floci-oci.base-url", "http://127.0.0.1:" + port);
        System.setProperty("floci-oci.hostname", "127.0.0.1");
        System.setProperty("floci-oci.tls.enabled", "false");
        System.setProperty("quarkus.log.console.stderr", "true");
        System.setProperty("quarkus.banner.enabled", "false");
        System.setProperty("floci-oci.storage.mode", directory == null ? "memory" : "persistent");
        if (directory != null) {
            System.setProperty("floci-oci.storage.persistent-path", directory);
            System.setProperty("floci-oci.storage.host-persistent-path", directory);
        }
        if (System.getenv("FLOCI_OCI_SERVICES_FUNCTIONS_MOCK") == null) {
            System.setProperty("floci-oci.services.functions.mock", "true");
        }
        if (System.getenv("FLOCI_OCI_SERVICES_OKE_MOCK") == null) {
            System.setProperty("floci-oci.services.oke.mock", "true");
        }
        if (System.getenv("FLOCI_OCI_DOCKER_DOCKER_HOST") == null
                && System.getenv("DOCKER_HOST") == null
                && !Files.exists(Path.of("/var/run/docker.sock"))) {
            System.setProperty("floci-oci.docker.docker-host", "tcp://127.0.0.1:2375");
        }
    }

    private static void failure(String kind, String message, int code) {
        // Messages are fixed strings, never arbitrary exception text or credentials.
        System.out.println("{\"ok\":false,\"error\":{\"kind\":\"" + kind
                + "\",\"message\":\"" + message + "\"}}");
        System.exit(code);
    }
}
