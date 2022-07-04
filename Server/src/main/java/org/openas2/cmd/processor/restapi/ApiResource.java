/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.openas2.cmd.processor.restapi;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.openas2.OpenAS2Exception;
import org.openas2.cert.AliasedCertificateFactory;
import org.openas2.cmd.CommandResult;
import org.openas2.cmd.processor.RestCommandProcessor;

import javax.annotation.security.RolesAllowed;
import jakarta.ws.rs.Consumes;

import jakarta.ws.rs.DefaultValue;


import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.HEAD;


import jakarta.ws.rs.PathParam;

import jakarta.ws.rs.core.Context;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Request;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.openas2.util.AS2Util;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author javier
 */
@Path("api")
public class ApiResource {

    /**
     * @return the processor
     */
    public static RestCommandProcessor getProcessor() {
        return processor;
    }

    /**
     * @param aProcessor the processor to set
     */
    public static void setProcessor(RestCommandProcessor aProcessor) {
        processor = aProcessor;
    }

    private static RestCommandProcessor processor;
    @Context
    UriInfo ui;
    @Context
    Request request;
    private final ObjectMapper mapper;

    public ApiResource() {

        mapper = new ObjectMapper();
        // enable pretty printing
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    @RolesAllowed({"ADMIN"})
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public CommandResult getVersion() {
        return new CommandResult(CommandResult.TYPE_OK, getProcessor().getSession().getAppTitle());
    }

    private CommandResult getCertificate(String itemId) throws Exception {
        try {
            List<String> params = new ArrayList<String>();
            params.add("view");
            params.add(itemId);
            CommandResult output = getProcessor().feedCommand("cert", params);
            Certificate cert = (Certificate) output.getResults().get(0);
            HashMap<String, String> map = new HashMap<>();
            map.put("data", Base64.getEncoder().encodeToString(cert.getEncoded()));
            map.put("alias", itemId);
            output.getResults().set(0, map);
            return output;
        } catch (Exception ex) {
            Logger.getLogger(ApiResource.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            throw ex;
            // return Response.status(506).entity( ex.getMessage()).build();
        }

    }

    @RolesAllowed({"ADMIN"})
    @GET
    @Path("/{resource}/{action}{id:(/[^/]+?)?}")
    @Produces(MediaType.APPLICATION_JSON)
    public CommandResult getCommand(@PathParam("resource") String resource, @PathParam("action") @DefaultValue("list") String action, @PathParam("id") String itemId) throws Exception {
        try {
            // TODO: Figure out a better way to return proper JSON objects instead of this hack
            if (action.equalsIgnoreCase("view") && resource.equalsIgnoreCase("cert") && (itemId != null && itemId.length() > 1)) {
                return this.getCertificate(itemId.substring(1));
            }
            List<String> params = new ArrayList<>();
            if (action != null) {
                params.add(action);
            }
            if (itemId != null && itemId.length() > 1) {
                params.add(itemId.substring(1));
            }
            Iterator<String> iter = ui.getQueryParameters().keySet().iterator();
            while (iter.hasNext()) {
                String valueKey = iter.next();
                String valueParam = ui.getQueryParameters().getFirst(valueKey);
                params.add(valueKey + "=" + valueParam);
            }
            CommandResult output = getProcessor().feedCommand(resource, params);
            return output;
        } catch (Exception ex) {
            Logger.getLogger(ApiResource.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            throw ex;
            // return Response.status(506).entity( ex.getMessage()).build();
        }

    }

    @RolesAllowed({"ADMIN"})
    @POST
    @Path("/{resource}/{action}{id:(/[^/]+?)?}")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public CommandResult postCommand(@PathParam("resource") String resource, @PathParam("action") @DefaultValue("list") String action, @PathParam("id") String itemId, MultivaluedMap<String, String> formParams) throws Exception {
        try {
            // TODO: Figure out a better way to return proper JSON objects instead of this hack
            if (action.equalsIgnoreCase("view") && resource.equalsIgnoreCase("cert")) {
                return this.getCertificate(itemId);
            }
            if (action.equalsIgnoreCase("importbystream") && resource.equalsIgnoreCase("cert")) {
                return this.importCertificateByStream(itemId.substring(1), formParams);
            }
            if (action.equalsIgnoreCase("importbyfile") && resource.equalsIgnoreCase("cert")) {
                return this.importCertificateByFileName(itemId.substring(1),formParams);
            }
            List<String> params = new ArrayList<String>();
            if (action != null) {
                params.add(action);
            }
            if (itemId != null && itemId.length() > 1) {
                params.add(itemId.substring(1));
            }
            Iterator<String> iter = ui.getQueryParameters().keySet().iterator();
            while (iter.hasNext()) {
                String valueKey = iter.next();
                String valueParam = ui.getQueryParameters().getFirst(valueKey);
                params.add(valueKey + "=" + valueParam);
            }
            int length = formParams.size();
            for (int index = 0; index < length; index++) {
                if (formParams.containsKey(String.valueOf(index))) {
                    params.add(formParams.getFirst(String.valueOf(index)));
                    formParams.remove(index);
                }
            }
            iter = formParams.keySet().iterator();
            while (iter.hasNext()) {
                String valueKey = iter.next();
                String valueParam = formParams.getFirst(valueKey);
                params.add(valueKey + "=" + valueParam);
            }
            CommandResult output = getProcessor().feedCommand(resource, params);
            return output;
        } catch (Exception ex) {
            Logger.getLogger(ApiResource.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            throw ex;
            // return Response.status(506).entity( ex.getMessage()).build();
        }
    }

    @RolesAllowed({"ADMIN"})
    @PUT
    @Path("/{resource}/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public CommandResult putCommand(@PathParam("resource") String resource, @PathParam("id") String itemId, MultivaluedMap<String, String> formParams) throws Exception {
        return postCommand(resource, "add", itemId, formParams);
    }

    @RolesAllowed({"ADMIN"})
    @DELETE
    @Path("/{resource}/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public CommandResult deleteCommand(@PathParam("resource") String resource, @PathParam("id") String itemId) throws Exception {
        return getCommand(resource, "delete", itemId);
    }

    @RolesAllowed({"ADMIN"})
    @HEAD
    @Path("/{resource}{action:(/[^/]+?)?}{id:(/[^/]+?)?}")
    public Response headCommand(@PathParam("resource") String command) {
        // Just an Empty response
        return Response.status(200).build();
    }

    private CommandResult importCertificateByStream(String itemId, MultivaluedMap<String, String> formParams) throws Exception {
        try {
            List<String> params = new ArrayList<String>();
            params.add("importbystream");
            params.add(itemId);
            String payload = formParams.getFirst("data");
            AliasedCertificateFactory certFx = (AliasedCertificateFactory) getProcessor().getSession().getCertificateFactory();
            ByteArrayInputStream bais = new ByteArrayInputStream(Base64.getDecoder().decode(payload));

            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            CommandResult cmdRes = new CommandResult(CommandResult.TYPE_OK, "Certificate(s) imported successfully");

            while (bais.available() > 0) {
                Certificate cert = cf.generateCertificate(bais);

                if (cert instanceof X509Certificate) {
                    certFx.addCertificate(itemId, (X509Certificate) cert, true);
                    cmdRes.getResults().add("Imported certificate: " + itemId);
                    return cmdRes;
                }
            }
            return new CommandResult(CommandResult.TYPE_ERROR, "No valid X509 certificates found");
        } catch (Exception ex) {
            Logger.getLogger(ApiResource.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            throw ex;
            // return Response.status(506).entity( ex.getMessage()).build();
        }
    }

    private CommandResult importCertificateByFileName(String itemId, MultivaluedMap<String, String> formParams) throws Exception {
        AliasedCertificateFactory certFx = (AliasedCertificateFactory) getProcessor().getSession().getCertificateFactory();
        String fileName = formParams.getFirst("fileName");
        String pwd = formParams.getFirst("password");
        try {
            if (fileName == null) {
                return new CommandResult(CommandResult.TYPE_ERROR, "Missing fileName.");
            }
            if ((fileName.endsWith(".p12") || fileName.endsWith(".pfx"))) {
                if (pwd == null) {
                    return new CommandResult(CommandResult.TYPE_ERROR, "KeyStore file missing password.");
                }
                return importPrivateKey(certFx, itemId, fileName, pwd);
            } else {
                return importCert(certFx,itemId,fileName);
            }
        } catch (IOException e) {
            return new CommandResult(CommandResult.TYPE_ERROR,"File not found: "+ fileName);
        }
    }

    private CommandResult importCert(AliasedCertificateFactory certFx, String alias, String fileName) throws IOException, CertificateException, OpenAS2Exception {
        FileInputStream fis = new FileInputStream(fileName);
        BufferedInputStream bis = new BufferedInputStream(fis);

        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");

        CommandResult cmdRes = new CommandResult(CommandResult.TYPE_OK, "Certificate(s) imported successfully");

        while (bis.available() > 0) {
            Certificate cert = cf.generateCertificate(bis);

            if (cert instanceof X509Certificate) {
                certFx.addCertificate(alias, (X509Certificate) cert, true);
                cmdRes.getResults().add("Imported certificate: " + cert.toString());

                return cmdRes;
            }
        }

        return new CommandResult(CommandResult.TYPE_ERROR, "No valid X509 certificates found");
    }
    private CommandResult importPrivateKey(AliasedCertificateFactory certFx, String alias, String filename, String password) throws Exception {
        KeyStore ks = AS2Util.getCryptoHelper().getKeyStore();
        ks.load(new FileInputStream(filename), password.toCharArray());

        Enumeration<String> aliases = ks.aliases();

        while (aliases.hasMoreElements()) {
            String certAlias = aliases.nextElement();
            Certificate cert = ks.getCertificate(certAlias);

            if (cert instanceof X509Certificate) {
                certFx.addCertificate(alias, (X509Certificate) cert, true);

                Key certKey = ks.getKey(certAlias, password.toCharArray());
                certFx.addPrivateKey(alias, certKey, password);

                return new CommandResult(CommandResult.TYPE_OK, "Imported certificate and key: " + cert.toString());
            }
        }

        return new CommandResult(CommandResult.TYPE_ERROR, "No valid X509 certificates found");

    }

}
