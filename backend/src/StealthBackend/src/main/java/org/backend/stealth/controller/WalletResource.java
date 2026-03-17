package org.backend.stealth.controller;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.util.Map;

@ApplicationScoped
@Path("/api/wallet")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class WalletResource {

    @ConfigProperty(name = "stealth.detect.script", defaultValue = "../../script/detect_public.py")
    String detectScript;

    @GET
    @Path("/scan")
    public Response scan(
        @QueryParam("descriptor") String descriptor,
        @DefaultValue("0") @QueryParam("offset") int offset,
        @DefaultValue("20") @QueryParam("count") int count
    ) {
        if (descriptor == null || descriptor.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("error", "descriptor query parameter is required"))
                .build();
        }

        if (offset < 0) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("error", "offset must be >= 0"))
                .build();
        }

        if (count <= 0) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("error", "count must be > 0"))
                .build();
        }

        if (count > 500) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("error", "count must be <= 500"))
                .build();
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(
                "python3",
                detectScript,
                descriptor,
                String.valueOf(offset),
                String.valueOf(count)
            );
            pb.redirectErrorStream(false);
            Process process = pb.start();

            String output = new String(process.getInputStream().readAllBytes());
            String stderr = new String(process.getErrorStream().readAllBytes());
            int exitCode = process.waitFor();

            if (exitCode != 0 || output.isBlank()) {
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", stderr.isBlank() ? "detect_public.py produced no output" : stderr.strip()))
                    .build();
            }

            return Response.ok(output).type(MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(Map.of("error", e.getMessage()))
                .build();
        }
    }
}
