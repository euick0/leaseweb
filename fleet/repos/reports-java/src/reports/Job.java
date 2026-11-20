package reports;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Internal reporting job. Other services in the cluster ask it to build
 * reports; it has no route from the internet.
 *
 * Logs the caller's X-Api-Version header with Log4j, so it carries the same
 * Log4Shell flaw as orders, but only callers inside the cluster can reach it.
 */
public final class Job {

    private static final Logger LOG = LogManager.getLogger(Job.class);

    private Job() {
    }

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/health", ex -> send(ex, 200, "ok\n"));
        server.createContext("/", Job::report);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        LOG.info("reports job listening on 8080");
    }

    private static void report(HttpExchange ex) throws IOException {
        String caller = ex.getRequestHeaders().getFirst("X-Api-Version");
        LOG.info("building monthly report for caller apiVersion={}", caller);
        send(ex, 200, "report queued\n");
    }

    private static void send(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}
