package de.fraunhofer.fokus.ids.utils.services.authService;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.ProxyGen;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.WebClient;

import java.nio.file.Path;

/**
 * @author Vincent Bohlen, vincent.bohlen@fokus.fraunhofer.de
 */
@ProxyGen
@VertxGen
public interface AuthAdapterService {

    @Fluent
    AuthAdapterService retrieveToken(Handler<AsyncResult<String>> readyHandler);

    @Fluent
    AuthAdapterService isAuthenticated(String token, Handler<AsyncResult<Void>> readyHandler);

    @GenIgnore
    static AuthAdapterService create(Vertx vertx,
                                     WebClient webClient,
                                     Path targetDirectory,
                                     JsonObject config,
                                     Handler<AsyncResult<AuthAdapterService>> readyHandler) {
        return new AuthAdapterServiceImpl(vertx, webClient, targetDirectory, config, readyHandler);
    }

    @GenIgnore
    static AuthAdapterService createProxy(Vertx vertx, String address) {
        return new AuthAdapterServiceVertxEBProxy(vertx, address);
    }

}
