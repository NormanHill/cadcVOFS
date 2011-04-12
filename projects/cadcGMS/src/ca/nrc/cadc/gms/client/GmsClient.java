/**
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2010.                            (c) 2010.
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 *  All rights reserved                  Tous droits réservés
 *
 *  NRC disclaims any warranties,        Le CNRC dénie toute garantie
 *  expressed, implied, or               énoncée, implicite ou légale,
 *  statutory, of any kind with          de quelque nature que ce
 *  respect to the software,             soit, concernant le logiciel,
 *  including without limitation         y compris sans restriction
 *  any warranty of merchantability      toute garantie de valeur
 *  or fitness for a particular          marchande ou de pertinence
 *  purpose. NRC shall not be            pour un usage particulier.
 *  liable in any event for any          Le CNRC ne pourra en aucun cas
 *  damages, whether direct or           être tenu responsable de tout
 *  indirect, special or general,        dommage, direct ou indirect,
 *  consequential or incidental,         particulier ou général,
 *  arising from the use of the          accessoire ou fortuit, résultant
 *  software.  Neither the name          de l'utilisation du logiciel. Ni
 *  of the National Research             le nom du Conseil National de
 *  Council of Canada nor the            Recherches du Canada ni les noms
 *  names of its contributors may        de ses  participants ne peuvent
 *  be used to endorse or promote        être utilisés pour approuver ou
 *  products derived from this           promouvoir les produits dérivés
 *  software without specific prior      de ce logiciel sans autorisation
 *  written permission.                  préalable et particulière
 *                                       par écrit.
 *
 *  This file is part of the             Ce fichier fait partie du projet
 *  OpenCADC project.                    OpenCADC.
 *
 *  OpenCADC is free software:           OpenCADC est un logiciel libre ;
 *  you can redistribute it and/or       vous pouvez le redistribuer ou le
 *  modify it under the terms of         modifier suivant les termes de
 *  the GNU Affero General Public        la “GNU Affero General Public
 *  License as published by the          License” telle que publiée
 *  Free Software Foundation,            par la Free Software Foundation
 *  either version 3 of the              : soit la version 3 de cette
 *  License, or (at your option)         licence, soit (à votre gré)
 *  any later version.                   toute version ultérieure.
 *
 *  OpenCADC is distributed in the       OpenCADC est distribué
 *  hope that it will be useful,         dans l’espoir qu’il vous
 *  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
 *  without even the implied             GARANTIE : sans même la garantie
 *  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
 *  or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
 *  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
 *  General Public License for           Générale Publique GNU Affero
 *  more details.                        pour plus de détails.
 *
 *  You should have received             Vous devriez avoir reçu une
 *  a copy of the GNU Affero             copie de la Licence Générale
 *  General Public License along         Publique GNU Affero avec
 *  with OpenCADC.  If not, see          OpenCADC ; si ce n’est
 *  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
 *                                       <http://www.gnu.org/licenses/>.
 *
 ************************************************************************
 */
package ca.nrc.cadc.gms.client;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.util.Collection;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;

import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.gms.GmsConsts;
import ca.nrc.cadc.gms.Group;
import ca.nrc.cadc.gms.GroupImpl;
import ca.nrc.cadc.gms.GroupReader;
import ca.nrc.cadc.gms.GroupWriter;
import ca.nrc.cadc.gms.GroupsReader;
import ca.nrc.cadc.gms.ReaderException;
import ca.nrc.cadc.gms.User;
import ca.nrc.cadc.gms.UserReader;
import ca.nrc.cadc.reg.client.RegistryClient;

/**
 * Client class for the GMS service. This class must be invoked from a
 * subject context and the subject must be authenticated with
 * X509Principals
 */
public class GmsClient
{
    private static Logger logger = Logger.getLogger(GmsClient.class);
    // private URL baseServiceURL;

    // socket factory to use when connecting
    SSLSocketFactory sf;

    private RegistryClient registryClient = new RegistryClient();

    /**
     * Ctor
     * 
     * @param baseServiceURL
     *            The
     * @deprecated Service URL resolved through the group ID (URI). Use
     *             the default constructor instead.
     */
    @Deprecated
    public GmsClient(final URL baseServiceURL)
    {
        // do nothing
    }

    /**
     * Default ctor
     */
    public GmsClient()
    {
        // nothing to do
    }

    /**
     * Obtain the Member for the given Group and Member IDs.
     * 
     * @param groupID
     *            The Group ID to check.
     * @param memberID
     *            The Member ID to check.
     * @return The User member instance for the given Member's ID.
     * @throws IllegalArgumentException
     *             If the Group ID, Member ID, or accepted baseServiceURL,
     *             or any combination of them produces an error.
     * @throws URISyntaxException
     * @throws AccessControlException
     *             If user not allow to access the resource
     */
    @Deprecated
    public User getMember(final URI groupID, final X500Principal memberID)
            throws IllegalArgumentException, URISyntaxException
    {
        final StringBuilder resourcePath = new StringBuilder(64);

        try
        {
            resourcePath.append("/members/");
            resourcePath.append(URLEncoder.encode(memberID.toString(),
                    "UTF-8"));
            resourcePath.append("/");
            resourcePath.append(URLEncoder.encode(groupID.getFragment(),
                    "UTF-8"));

            final URL resourceURL = new URL(getServiceURL(groupID)
                    + resourcePath.toString());
            logger.debug("getMember(), URL=" + resourceURL);
            HttpURLConnection connection = openConnection(resourceURL);
            connection.setRequestMethod("GET");
            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(false);
            connection.connect();

            String responseMessage = connection.getResponseMessage();
            int responseCode = connection.getResponseCode();
            logger.debug("getMember(), response code: " + responseCode);
            logger.debug("getMember(), response message: "
                    + responseMessage);

            switch (responseCode)
            {
                case HttpURLConnection.HTTP_OK:
                    return constructUser(connection);
                case HttpURLConnection.HTTP_NOT_FOUND:
                    return null;
                case HttpURLConnection.HTTP_FORBIDDEN:
                    throw new AccessControlException(responseMessage);
                default:
                    throw new RuntimeException(
                            "Unexpected failure mode: " + responseMessage
                                    + "(" + responseCode + ")");
            }

        }
        catch (ReaderException e)
        {
            final String message = String.format(
                    "The supplied URL (%s) cannot be read from.",
                    getServiceURL(groupID).toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to get member", e);
            throw new IllegalArgumentException(message, e);
        }
        catch (IOException e)
        {
            final String message = String.format(
                    "Client BUG: The supplied URL (%s) cannot "
                            + "be hit.", getServiceURL(groupID)
                            .toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to get member", e);
            throw new IllegalArgumentException(message, e);
        }
    }

    /**
     * Returns true of the user identified by memberID is a member of the
     * group identified by groupID. Otherwise, false is returned.
     * 
     * @param groupID
     *            The group identifier.
     * @param memberID
     *            The member identifier.
     * @return true if the user is a member of the group.
     * @throws IllegalArgumentException
     *             If the Group ID, Member ID, or accepted baseServiceURL,
     *             or any combination of them produces an error.
     * @throws AccessControlException
     *             if caller is not permitted access to the group
     * @throws IOException
     *             if the call to the GMS service fails
     * @throws URISyntaxException
     *             for group URI
     * 
     */
    public boolean isMember(URI groupID, X500Principal memberID)
            throws AccessControlException, IOException,
            URISyntaxException
    {
        final StringBuilder resourcePath = new StringBuilder(64);
        try
        {
            resourcePath.append("/groups/");
            resourcePath.append(URLEncoder.encode(groupID.getFragment(),
                    "UTF-8"));
            resourcePath.append("/");
            resourcePath.append(URLEncoder.encode(memberID.toString(),
                    "UTF-8"));

            URL resourceURL = new URL(getServiceURL(groupID)
                    + resourcePath.toString());
            logger.debug("isMember(), URL=" + resourceURL);
            HttpURLConnection connection = openConnection(resourceURL);
            connection.setRequestMethod("HEAD");
            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(false);
            connection.connect();

            String responseMessage = connection.getResponseMessage();
            int responseCode = connection.getResponseCode();
            logger.debug("isMember(), response code: " + responseCode);
            logger.debug("isMember(), response message: "
                    + responseMessage);

            switch (responseCode)
            {
                case HttpURLConnection.HTTP_OK:
                    return true;
                case HttpURLConnection.HTTP_NOT_FOUND:
                    return false;
                case HttpURLConnection.HTTP_FORBIDDEN:
                    throw new AccessControlException(responseMessage);
                default:
                    throw new RuntimeException(
                            "Unexpected failure mode: " + responseMessage
                                    + "(" + responseCode + ")");
            }
        }
        catch (MalformedURLException e)
        {
            // this is not possible without a serious bug in the above
            // code
            String msg = getServiceURL(groupID) + resourcePath.toString();
            throw new RuntimeException("BUG: generated an illegal URL "
                    + msg);
        }
    }

    private URL getServiceURL(URI groupID)
            throws IllegalArgumentException
    {
        try
        {
            // create the URI for the service, e.g. drop the fragment
            URI serviceURI = new URI(groupID.getScheme(), groupID
                    .getSchemeSpecificPart(), null); // drop fragment
            URL baseURL = registryClient.getServiceURL(serviceURI, "https");
            return baseURL;
        }
        catch (Exception ex)
        {
            throw new IllegalArgumentException("Invalid URI: " + groupID, ex);
        }
    }

    /**
     * Get the group identified by groupID. Associated members will be
     * included.
     * 
     * Note - It is expected that the URI is already encoded!
     * 
     * @param groupID
     *            Identifies the group.
     * @return The group, or null if not found. *
     * @throws URISyntaxException
     * @throws IllegalArgumentException
     *             If the Group ID, Member ID, or accepted baseServiceURL,
     *             or any combination of them produces an error.
     * @throws AccessControlException
     *             If user not allow to access the resource
     * 
     */
    public Group getGroup(URI groupID) throws URISyntaxException
    {
        final StringBuilder resourcePath = new StringBuilder(64);

        try
        {
            resourcePath.append("/groups/");
            resourcePath.append(URLEncoder.encode(groupID.getFragment(),
                    "UTF-8"));

            final URL resourceURL = new URL(getServiceURL(groupID)
                    + resourcePath.toString());
            logger.debug("getGroup(), URL=" + resourceURL);
            HttpURLConnection connection = openConnection(resourceURL);
            connection.setRequestMethod("GET");
            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(false);
            connection.connect();

            String responseMessage = connection.getResponseMessage();
            int responseCode = connection.getResponseCode();
            logger.debug("getGroup(), response code: " + responseCode);
            logger.debug("getGroup(), response message: "
                    + responseMessage);

            switch (responseCode)
            {
                case HttpURLConnection.HTTP_OK:
                    return constructGroup(connection);
                case HttpURLConnection.HTTP_NOT_FOUND:
                    logger.debug(getErrorMessage(connection));
                    return null;
                case HttpURLConnection.HTTP_FORBIDDEN:
                    throw new AccessControlException(responseMessage);
                default:
                    throw new RuntimeException(
                            "Unexpected failure mode: " + responseMessage
                                    + "(" + responseCode + ")");
            }

        }
        catch (ReaderException e)
        {
            final String message = String.format(
                    "The supplied URL (%s) cannot be read from.",
                    getServiceURL(groupID).toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to get group", e);
            throw new IllegalArgumentException(message, e);
        }
        catch (IOException e)
        {
            final String message = String.format(
                    "Client BUG: The supplied URL (%s) cannot "
                            + "be hit.", getServiceURL(groupID)
                            .toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to get group", e);
            throw new IllegalArgumentException(message, e);
        }
    }

    /**
     * Create the group identified by groupID.
     * 
     * It is expected that the Group's URI ID will be encoded by the
     * caller.
     * 
     * @param group
     *            Group to create. Group cannot be null. Server generates
     *            group ID if the ID of the group argument does not
     *            contain a fragment (e.g. is only the URI of the
     *            service).
     * @return The newly created group group
     * @throws IllegalArgumentException
     *             If the Group ID, or accepted baseServiceURL, or any
     *             combination of them produces an error.
     * @throws AccessControlException
     *             If user not allow to access the resource
     */
    public Group createGroup(final Group group)
            throws IllegalArgumentException
    {
        final StringBuilder resourcePath = new StringBuilder(64);
        resourcePath.append("/groups");

        try
        {
            final URL resourceURL = new URL(getServiceURL(group.getID())
                    + resourcePath.toString());
            logger.debug("createGroup(), URL=" + resourceURL);
            HttpURLConnection connection = openConnection(resourceURL);
            connection.setRequestMethod("PUT");
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setUseCaches(false);

            OutputStreamWriter out = new OutputStreamWriter(connection
                    .getOutputStream());

            GroupWriter.write(group, out);
            out.flush();
            out.close();

            String responseMessage = connection.getResponseMessage();
            int responseCode = connection.getResponseCode();
            logger.debug("createGroup(), response code: " + responseCode);
            logger.debug("createGroup(), response message: "
                    + responseMessage);

            switch (responseCode)
            {
                case HttpURLConnection.HTTP_CREATED:
                    String location = connection
                            .getHeaderField("Location");
                    return getGroup(new URI(location));
                case HttpURLConnection.HTTP_OK:
                    // break intentionally left out
                case HttpURLConnection.HTTP_CONFLICT:
                    // break intentionally left out
                case HttpURLConnection.HTTP_NOT_FOUND:
                    // parent node not found
                    // break intentionally left out
                case HttpURLConnection.HTTP_BAD_REQUEST:
                    // duplicate group
                    throw new IllegalArgumentException(responseMessage
                            + ": " + getErrorMessage(connection));

                case HttpURLConnection.HTTP_FORBIDDEN:
                    throw new AccessControlException(responseMessage);
                default:
                    throw new RuntimeException(
                            "Unexpected failure mode: " + responseMessage
                                    + "(" + responseCode + ")");
            }
        }
        catch (IOException e)
        {
            final String message = String.format(
                    "Client BUG: The supplied URL (%s) cannot "
                            + "be hit.", getServiceURL(group.getID())
                            .toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to create group", e);
            throw new IllegalStateException(message, e);
        }
        catch (URISyntaxException e)
        {
            final String message = String
                    .format("Cannot follow URI to the created group");
            logger.debug("Failed to get the created group", e);
            throw new IllegalStateException(message, e);
        }
    }

    /**
     * Update (POST) the changes to the given Group.
     * 
     * @param group
     *            The group, modified.
     * @return The updated group.
     * @throws IllegalArgumentException
     *             If the Group ID, or accepted baseServiceURL, or any
     *             combination of them produces an error.
     * @throws AccessControlException
     *             If user not allow to access the resource
     */
    public Group updateGroup(final Group group)
            throws IllegalArgumentException
    {
        final StringBuilder resourcePath = new StringBuilder(64);
        resourcePath.append("/groups");

        try
        {
            String groupID = group.getID().getFragment();

            resourcePath.append("/");
            resourcePath.append(URLEncoder.encode(groupID, "UTF-8"));

            final URL resourceURL = new URL(getServiceURL(group.getID())
                    + resourcePath.toString());
            logger.debug("createGroup(), URL=" + resourceURL);
            HttpURLConnection connection = openConnection(resourceURL);
            connection.setRequestMethod("POST");
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "text/xml");
            connection.setUseCaches(false);

            OutputStreamWriter out = new OutputStreamWriter(connection
                    .getOutputStream());
            GroupWriter.write(group, out);
            out.close();

            String responseMessage = connection.getResponseMessage();
            int responseCode = connection.getResponseCode();
            logger.debug("createGroup(), response code: " + responseCode);
            logger.debug("createGroup(), response message: "
                    + responseMessage);

            switch (responseCode)
            {
                case HttpURLConnection.HTTP_CREATED:
                    String location = connection
                            .getHeaderField("Location");
                    return getGroup(new URI(location));
                case HttpURLConnection.HTTP_CONFLICT:
                    // break intentionally left out
                case HttpURLConnection.HTTP_NOT_FOUND:
                    // parent node not found
                    // break intentionally left out
                case HttpURLConnection.HTTP_BAD_REQUEST:
                    // duplicate group
                    throw new IllegalArgumentException(responseMessage
                            + ": " + getErrorMessage(connection));
                case HttpURLConnection.HTTP_FORBIDDEN:
                    throw new AccessControlException(responseMessage);
                default:
                    throw new RuntimeException(
                            "Unexpected failure mode: " + responseMessage
                                    + "(" + responseCode + ")");
            }
        }
        catch (IOException e)
        {
            final String message = String.format(
                    "Client BUG: The supplied URL (%s) cannot "
                            + "be hit.", getServiceURL(group.getID())
                            .toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to create group", e);
            throw new IllegalStateException(message, e);
        }
        catch (URISyntaxException e)
        {
            final String message = String
                    .format("Cannot follow URI to the created group");
            logger.debug("Failed to get the created group", e);
            throw new IllegalStateException(message, e);
        }
    }

    /**
     * Deletes the group identified by groupID.
     * 
     * @param groupID
     *            Identifies the group.
     * @throws IllegalArgumentException
     *             If the Group ID, or accepted baseServiceURL, or any
     *             combination of them produces an error.
     * @throws URISyntaxException
     * @throws AccessControlException
     *             If user not allow to access the resource
     */
    public void deleteGroup(URI groupID) throws IllegalArgumentException,
            URISyntaxException
    {
        final StringBuilder resourcePath = new StringBuilder(64);
        try
        {
            resourcePath.append("/groups/");
            resourcePath.append(URLEncoder.encode(groupID.getFragment(),
                    "UTF-8"));

            final URL resourceURL = new URL(getServiceURL(groupID)
                    + resourcePath.toString());
            logger.debug("deleteGroup(), URL=" + resourceURL);
            HttpURLConnection connection = openConnection(resourceURL);
            connection.setRequestMethod("DELETE");
            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(false);
            connection.connect();

            String responseMessage = connection.getResponseMessage();
            int responseCode = connection.getResponseCode();
            logger.debug("deleteGroup(), response code: " + responseCode);
            logger.debug("deleteGroup(), response message: "
                    + responseMessage);

            switch (responseCode)
            {
                case HttpURLConnection.HTTP_OK:
                    return;
                case HttpURLConnection.HTTP_CONFLICT:
                    // break intentionally left out
                case HttpURLConnection.HTTP_NOT_FOUND:
                    // parent node not found
                    // break intentionally left out
                case HttpURLConnection.HTTP_BAD_REQUEST:
                    // duplicate group
                    throw new IllegalArgumentException(responseMessage
                            + ": " + getErrorMessage(connection));
                case HttpURLConnection.HTTP_FORBIDDEN:
                    throw new AccessControlException(responseMessage);
                default:
                    throw new RuntimeException(
                            "Unexpected failure mode: " + responseMessage
                                    + "(" + responseCode + ")");
            }
        }
        catch (MalformedURLException e)
        {
            final String message = String.format(
                    "The supplied URL (%s) cannot be used.",
                    getServiceURL(groupID).toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to delete group", e);
            throw new IllegalArgumentException(message, e);
        }
        catch (IOException e)
        {
            final String message = String.format(
                    "Client BUG: The supplied URL (%s) cannot "
                            + "be hit.", getServiceURL(groupID)
                            .toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to delete group", e);
            throw new IllegalArgumentException(message, e);
        }
    }

    /**
     * Updates the group identified by groupID.
     * 
     * @param group
     *            Group to set. Cannot be null.
     * @return True if update was successful, False otherwise.
     * @throws IllegalArgumentException
     *             If the Group ID, or accepted baseServiceURL, or any
     *             combination of them produces an error.
     * @throws URISyntaxException
     * @throws AccessControlException
     *             If user not allow to access the resource
     */
    public boolean setGroup(Group group) throws IllegalArgumentException,
            URISyntaxException
    {
        final StringBuilder resourcePath = new StringBuilder(64);
        try
        {
            resourcePath.append("/groups/");
            resourcePath.append(URLEncoder.encode(group.getID()
                    .getFragment(), "UTF-8"));

            final URL resourceURL = new URL(getServiceURL(group.getID())
                    + resourcePath.toString());
            logger.debug("setGroup(), URL=" + resourceURL);
            HttpURLConnection connection = openConnection(resourceURL);
            connection.setRequestMethod("POST");
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "text/xml");
            connection.setUseCaches(false);

            OutputStreamWriter out = new OutputStreamWriter(connection
                    .getOutputStream());
            GroupWriter.write(group, out);
            out.close();

            String responseMessage = connection.getResponseMessage();
            int responseCode = connection.getResponseCode();
            logger.debug("setGroup(), response code: " + responseCode);
            logger.debug("setGroup(), response message: "
                    + responseMessage);

            switch (responseCode)
            {
                case HttpURLConnection.HTTP_OK:
                    return true;
                case HttpURLConnection.HTTP_CONFLICT:
                    // break intentionally left out
                case HttpURLConnection.HTTP_NOT_FOUND:
                    // parent node not found
                    // break intentionally left out
                case HttpURLConnection.HTTP_BAD_REQUEST:
                    // duplicate group
                    throw new IllegalArgumentException(responseMessage
                            + ": " + getErrorMessage(connection));
                case HttpURLConnection.HTTP_FORBIDDEN:
                    throw new AccessControlException(responseMessage);
                default:
                    throw new RuntimeException(
                            "Unexpected failure mode: " + responseMessage
                                    + "(" + responseCode + ")");
            }

        }
        catch (IOException e)
        {
            final String message = String.format(
                    "Client BUG: The supplied URL (%s) cannot "
                            + "be hit.", getServiceURL(group.getID())
                            .toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to seet group", e);
            throw new IllegalStateException(message, e);
        }
    }

    /**
     * Get groups the the user is member of.
     * 
     * @param userID
     *            Identifies the user.
     * @param serviceURI
     *            the URI of the service
     * @return The User with all the groups he's member of, or null if not
     *         found. *
     * @throws IllegalArgumentException
     *             If the User ID, or accepted baseServiceURL, or any
     *             combination of them produces an error.
     * @throws AccessControlException
     *             If user not allow to access the resource
     * 
     */
    public User getGMSMembership(X500Principal userID, URI serviceURI)
    {
       return getGMSMembership(userID, getServiceURL(serviceURI)); 
    }


    /**
     * Get groups the the user is member of.
     * 
     * @param userID
     *            Identifies the user.
     * @param baseURL
     *            the base URL of the service that host the groups
     * @return The User with all the groups he's member of, or null if not
     *         found. *
     * @throws IllegalArgumentException
     *             If the User ID, or accepted baseServiceURL, or any
     *             combination of them produces an error.
     * @throws AccessControlException
     *             If user not allow to access the resource
     * 
     */
    public User getGMSMembership(X500Principal userID, URL baseURL)
    {
        final StringBuilder resourcePath = new StringBuilder(64);

        try
        {
            resourcePath.append("/members/");
            resourcePath.append(URLEncoder.encode(userID.toString(),
                    "UTF-8"));
            final URL resourceURL = new URL(baseURL
                    + resourcePath.toString());
            logger.debug("getGMSMembership(), URL=" + resourceURL);
            HttpURLConnection connection = openConnection(resourceURL);
            connection.setRequestMethod("GET");
            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(false);
            connection.connect();

            String responseMessage = connection.getResponseMessage();
            int responseCode = connection.getResponseCode();
            logger.debug("getGMSMembership(), response code: "
                    + responseCode);
            logger.debug("getGMSMembership(), response message: "
                    + responseMessage);

            switch (responseCode)
            {
                case HttpURLConnection.HTTP_OK:
                    return constructUser(connection);
                case HttpURLConnection.HTTP_NOT_FOUND:
                    return null;
                case HttpURLConnection.HTTP_FORBIDDEN:
                    throw new AccessControlException(responseMessage);
                default:
                    throw new RuntimeException(
                            "Unexpected failure mode: " + responseMessage
                                    + "(" + responseCode + ")");
            }

        }
        catch (ReaderException e)
        {
            final String message = String.format(
                    "The supplied URL (%s) cannot be read from.", baseURL
                            .toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to get group", e);
            throw new IllegalArgumentException(message, e);
        }
        catch (IOException e)
        {
            final String message = String.format(
                    "Client BUG: The supplied URL (%s) cannot "
                            + "be hit.", baseURL.toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to get group", e);
            throw new IllegalArgumentException(message, e);
        }
    }

    /**
     * Adds a new member to a group
     * 
     * @param groupID
     *            The group identifier.
     * @param memberID
     *            The member identifier.
     * @return true if the user is successfully added to the group.
     * @throws URISyntaxException
     * @throws IllegalArgumentException
     *             If the Group ID, Member ID, or accepted baseServiceURL,
     *             or any combination of them produces an error.
     * @throws AccessControlException
     *             If user not allow to access the resource
     */
    public boolean addMember(URI groupID, X500Principal memberID)
            throws URISyntaxException
    {
        final StringBuilder resourcePath = new StringBuilder(64);
        try
        {
            resourcePath.append("/groups/");
            resourcePath.append(URLEncoder.encode(groupID.getFragment(),
                    "UTF-8"));
            resourcePath.append("/");
            resourcePath.append(URLEncoder.encode(memberID.toString(),
                    "UTF-8"));

            final URL resourceURL = new URL(getServiceURL(groupID)
                    + resourcePath.toString());
            logger.debug("addMember(), URL=" + resourceURL);
            HttpURLConnection connection = openConnection(resourceURL);
            connection.setRequestMethod("POST");
            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(false);
            connection.connect();

            String responseMessage = connection.getResponseMessage();
            int responseCode = connection.getResponseCode();
            logger.debug("addMember(), response code: " + responseCode);
            logger.debug("addMember(), response message: "
                    + responseMessage);

            switch (responseCode)
            {
                case HttpURLConnection.HTTP_CREATED:
                    return true;
                case HttpURLConnection.HTTP_OK:
                case HttpURLConnection.HTTP_BAD_REQUEST:
                case HttpURLConnection.HTTP_NOT_FOUND:
                    return false;
                case HttpURLConnection.HTTP_FORBIDDEN:
                    throw new AccessControlException(responseMessage);
                default:
                    throw new RuntimeException(
                            "Unexpected failure mode: " + responseMessage
                                    + "(" + responseCode + ")");
            }
        }
        catch (MalformedURLException e)
        {
            final String message = String.format(
                    "The supplied URL (%s) cannot be used.",
                    getServiceURL(groupID).toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to check membership", e);
            throw new IllegalArgumentException(message, e);
        }
        catch (IOException e)
        {
            final String message = String.format(
                    "Client BUG: The supplied URL (%s) cannot "
                            + "be hit.", getServiceURL(groupID)
                            .toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to check membership", e);
            throw new IllegalArgumentException(message, e);
        }
    }

    /**
     * Deletes a user from a group
     * 
     * @param groupID
     *            The group identifier.
     * @param memberID
     *            The member identifier.
     * @return true if the user is successfully removed from the group
     * @throws URISyntaxException
     * @throws IllegalArgumentException
     *             If the Group ID, Member ID, or accepted baseServiceURL,
     *             or any combination of them produces an error.
     * @throws AccessControlException
     *             If user not allow to access the resource
     */
    public boolean removeMember(URI groupID, X500Principal memberID)
            throws URISyntaxException
    {
        final StringBuilder resourcePath = new StringBuilder(64);
        try
        {
            resourcePath.append("/groups/");
            resourcePath.append(URLEncoder.encode(groupID.getFragment(),
                    "UTF-8"));
            resourcePath.append("/");
            resourcePath.append(URLEncoder.encode(memberID.toString(),
                    "UTF-8"));

            final URL resourceURL = new URL(getServiceURL(groupID)
                    + resourcePath.toString());
            logger.debug("removeMember(), URL=" + resourceURL);
            HttpURLConnection connection = openConnection(resourceURL);
            connection.setRequestMethod("DELETE");
            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(false);
            connection.connect();

            String responseMessage = connection.getResponseMessage();
            int responseCode = connection.getResponseCode();
            logger
                    .debug("removeMember(), response code: "
                            + responseCode);
            logger.debug("removeMember(), response message: "
                    + responseMessage);

            switch (responseCode)
            {
                case HttpURLConnection.HTTP_OK:
                    return true;
                case HttpURLConnection.HTTP_BAD_REQUEST:
                case HttpURLConnection.HTTP_NOT_FOUND:
                    return false;
                case HttpURLConnection.HTTP_FORBIDDEN:
                    throw new AccessControlException(responseMessage);
                default:
                    throw new RuntimeException(
                            "Unexpected failure mode: " + responseMessage
                                    + "(" + responseCode + ")");
            }
        }
        catch (MalformedURLException e)
        {
            final String message = String.format(
                    "The supplied URL (%s) cannot be used.",
                    getServiceURL(groupID).toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to check membership", e);
            throw new IllegalArgumentException(message, e);
        }
        catch (IOException e)
        {
            final String message = String.format(
                    "Client BUG: The supplied URL (%s) cannot "
                            + "be hit.", getServiceURL(groupID)
                            .toExternalForm()
                            + resourcePath.toString());
            logger.debug("Failed to check membership", e);
            throw new IllegalArgumentException(message, e);
        }
    }

    /**
     * Build a User member from the given URL.
     * 
     * @param connection
     *            The HttpURLConnection used to retrieve data. Caller must
     *            call and check the return code of the connection.
     * @return User instance, or null if none available.
     * @throws ReaderException
     *             If the URL's response could not be read.
     * @throws IOException
     *             For any unforeseen I/O errors.
     */
    private User constructUser(final HttpURLConnection connection)
            throws IOException, ReaderException
    {
        final User member;
        InputStream inputStream = connection.getInputStream();

        try
        {
            member = UserReader.read(inputStream);
        }
        catch (URISyntaxException e)
        {
            final String message = String
                    .format("Cannot construct user with data from server");
            logger.debug("Failed to get group", e);
            throw new IllegalArgumentException(message, e);
        }
        finally
        {
            try
            {
                if (inputStream != null)
                {
                    inputStream.close();
                }
            }
            catch (IOException e)
            {
                // Don't worry about it.
            }
        }

        return member;
    }

    /**
     * Build a Group from the given URL.
     * 
     * @param connection
     *            The HttpURLConnection used to retrieve data. Caller must
     *            call and check the return code of the connection.
     * @return Group instance, or null if none available.
     * @throws ReaderException
     *             If the URL's response could not be read.
     * @throws IOException
     *             For any unforeseen I/O errors.
     */
    private Group constructGroup(final HttpURLConnection connection)
            throws IOException, ReaderException
    {
        final Group group;
        InputStream inputStream = connection.getInputStream();

        try
        {
            group = GroupReader.read(inputStream);
        }
        catch (URISyntaxException e)
        {
            final String message = String
                    .format("Cannot construct group with data from server");
            logger.debug("Failed to get group", e);
            throw new IllegalArgumentException(message, e);
        }
        finally
        {
            try
            {
                if (inputStream != null)
                {
                    inputStream.close();
                }
            }
            catch (IOException e)
            {
                // Don't worry about it.
            }
        }

        return group;
    }

    /**
     * Open a HttpsURLConnection with a SocketFactory created based on
     * user credentials.
     * 
     * @param url
     *            The URL to open a connection to.
     * @return UTLConnection returns an open https connection to URL
     * @throws IOException
     *             If the connection cannot be established.
     */
    protected HttpsURLConnection openConnection(final URL url)
            throws IOException
    {
        if (!url.getProtocol().equals("https"))
        {
            throw new IllegalStateException("Wrong protocol: "
                    + url.getProtocol() + ". GMS works on https only");
        }
        if (sf == null)
        {
            // lazy initialization of socket factory
            AccessControlContext ac = AccessController.getContext();
            Subject subject = Subject.getSubject(ac);
            sf = SSLUtil.getSocketFactory(subject);
        }
        HttpsURLConnection con = (HttpsURLConnection) url
                .openConnection();
        if (sf != null)
            con.setSSLSocketFactory(sf);
        return con;
    }


    /**
     * Get groups owned by a user.
     * 
     * @param x500Principal
     *            The principal of the owner
     * @param serviceURI
     *            The URI of the service that hosts the groups
     * @return Collection of Group object
     */
    public Collection<Group> getGroups(final X500Principal x500Principal,
            URI serviceURI)
    {
         return getGroups(x500Principal, getServiceURL(serviceURI));
    }


    /**
     * Get groups owned by a user.
     * 
     * @param x500Principal
     *            The principal of the owner
     * @param baseURL
     *            The URL of the service that hosts the groups
     * @return Collection of Group object
     */
    public Collection<Group> getGroups(final X500Principal x500Principal,
            URL baseURL)
    {
        if (x500Principal == null)
            throw new RuntimeException(
                    "Cannot get groups with a null X500Principal.");

        Collection<Group> groups = null;

        StringBuffer resourcePath = new StringBuffer("/groups?");
        try
        {
            resourcePath.append(URLEncoder.encode(
                    GmsConsts.PROPERTY_OWNER_DN, "UTF-8"));
            resourcePath.append("=");
            resourcePath.append(URLEncoder.encode(x500Principal
                    .getName(X500Principal.CANONICAL), "UTF-8"));
        }
        catch (UnsupportedEncodingException e)
        {
            // this should not happen as the DN should be always valid.
            throw new RuntimeException(
                    "Error encoding distinguished name query.", e);
        }

        try
        {
            final URL resourceURL = new URL(baseURL
                    + resourcePath.toString());
            logger.debug("getGroup(), URL=" + resourceURL);
            // Always use secure HTTP connection
            HttpsURLConnection sslConnection = openConnection(resourceURL);

            sslConnection.setRequestMethod("GET");
            sslConnection.setUseCaches(false);
            sslConnection.setDoInput(true);
            sslConnection.setDoOutput(false);
            sslConnection.connect();

            String responseMessage = sslConnection.getResponseMessage();
            int responseCode = sslConnection.getResponseCode();
            logger.debug("getGroup(), response code: " + responseCode);
            logger.debug("getGroup(), response message: "
                    + responseMessage);

            switch (responseCode)
            {
                case HttpURLConnection.HTTP_OK:
                    InputStream is = sslConnection.getInputStream();
                    try
                    {
                        groups = GroupsReader.read(is);
                    }
                    catch (Exception e)
                    {
                        final String message = String
                                .format("Error occurs reading/processing server response.");
                        logger.debug("Failed to get groups", e);
                        throw new IllegalArgumentException(message, e);
                    }
                    finally
                    {
                        if (is != null)
                            is.close();
                    }
                    return groups;
                case HttpURLConnection.HTTP_NOT_FOUND:
                    return null;
                case HttpURLConnection.HTTP_FORBIDDEN:
                    throw new AccessControlException(responseMessage);
                default:
                    throw new RuntimeException(
                            "Unexpected failure mode: " + responseMessage
                                    + "(" + responseCode + ")");
            }
        }
        catch (IOException e)
        {
            final String message = String.format(
                    "Client BUG: The supplied URL (%s) cannot "
                            + "be hit.", baseURL.toExternalForm()
                            + resourcePath);
            logger.debug("Failed to get group", e);
            throw new IllegalArgumentException(message, e);
        }
    }

    /**
     * @param sslSocketFactory
     *            the sslSocketFactory to set
     */
    public void setSslSocketFactory(SSLSocketFactory sslSocketFactory)
    {
        this.sf = sslSocketFactory;
    }

    /**
     * @return the sslSocketFactory
     */
    public SSLSocketFactory getSslSocketFactory()
    {
        return sf;
    }

    /**
     * Returns the error message from connection.
     * 
     * @param connection
     * @return error message
     */
    private String getErrorMessage(HttpURLConnection connection)
    {
        String errorMsg = "No error message";
        BufferedInputStream is = new BufferedInputStream(connection
                .getErrorStream());
        Writer writer = new StringWriter();

        char[] buffer = new char[1024];
        try
        {
            Reader reader = new BufferedReader(new InputStreamReader(is,
                    "UTF-8"));
            int n;
            while ((n = reader.read(buffer)) != -1)
            {
                writer.write(buffer, 0, n);
            }
            errorMsg = writer.toString();
        }
        catch (Exception ex)
        {
            errorMsg = "No error message found due: " + ex.getMessage();
            logger.debug(errorMsg, ex);
        }
        // no need for finally since is is created locally

        return errorMsg;
    }

}
