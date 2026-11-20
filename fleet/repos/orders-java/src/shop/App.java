package shop;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;

/**
 * Orders API of the demo shop. Public, behind its gateway.
 *
 * Logs the X-Api-Version header and the query string of every request with
 * Log4j, which makes it vulnerable to Log4Shell on log4j-core 2.14.1.
 */
public final class App {

    private static final Logger LOG = LogManager.getLogger(App.class);

    private App() {
    }

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/health", ex -> send(ex, 200, "ok\n"));
        server.createContext("/version", App::version);
        server.createContext("/", App::orders);
        server.setExecutor(Executors.newFixedThreadPool(16));
        server.start();
        LOG.info("orders listening on 8080");
    }

    private static void orders(HttpExchange ex) throws IOException {
        String apiVersion = ex.getRequestHeaders().getFirst("X-Api-Version");
        String rawQuery = ex.getRequestURI().getRawQuery();
        String query = rawQuery == null ? "" : URLDecoder.decode(rawQuery, StandardCharsets.UTF_8);
        LOG.info("orders request path={} apiVersion={} query={}", ex.getRequestURI().getPath(), apiVersion, query);
        send(ex, 200, "{\"orders\":[{\"id\":1001,\"total\":\"120.00 EUR\"}]}\n");
    }

    private static void version(HttpExchange ex) throws IOException {
        String log4j = LoggerContext.class.getPackage().getImplementationVersion();
        send(ex, 200, "{\"log4j\":\"" + log4j + "\"}\n");
    }

    private static void send(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", body.startsWith("{") ? "application/json" : "text/plain");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}
