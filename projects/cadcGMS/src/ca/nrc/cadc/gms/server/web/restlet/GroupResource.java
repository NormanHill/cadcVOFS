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
package ca.nrc.cadc.gms.server.web.restlet;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;

import org.apache.log4j.Logger;
import org.jdom.Document;
import org.restlet.data.Status;
import org.restlet.resource.Delete;
import org.restlet.resource.Post;
import org.restlet.resource.Put;
import org.restlet.representation.Representation;

import ca.nrc.cadc.gms.*;
import ca.nrc.cadc.gms.server.GroupService;


public class GroupResource extends AbstractResource
{
    private final static Logger LOGGER = Logger
            .getLogger(GroupResource.class);

    protected GroupService groupService;

    private Group group;

    /**
     * Hidden constructor for JavaBean tools.
     */
    GroupResource()
    {
        super();
    }

    /**
     * Full constructor.
     * 
     * @param groupService
     *            The GroupService instance.
     */
    public GroupResource(final GroupService groupService)
    {
        this.groupService = groupService;
    }

    /**
     * Get a reference to the resource identified by the user.
     */
    @Override
    protected boolean obtainResource()
    {
        LOGGER.debug("Enter GroupResource.obtainResource()");
        String groupMemberID = null;
        String groupID = null;

        try
        {
//            groupID = URLDecoder.decode(getGroupID(), "UTF-8");
            groupID = getGroupID();
            LOGGER.debug(String.format("groupID: %s", groupID));

            group = getGroupService().getGroup(
                    new URI(groupService.getGroupUriPrefix() + groupID));
            return true;
        }
        catch (final InvalidGroupException e)
        {
            final String message = String.format(
                    "No such Group with ID %s", groupID);
            processError(e, Status.CLIENT_ERROR_NOT_FOUND, message);
        }
        catch (AuthorizationException e)
        {
            final String message = String.format(
                    "You are not authorized to view Member ID "
                            + "'%s' of Group ID '%s'.", groupMemberID,
                    groupID);
            processError(e, Status.CLIENT_ERROR_UNAUTHORIZED, message);
        }
//        catch (UnsupportedEncodingException e)
//        {
//            final String message = String.format(
//                    "Could not URL decode groupMemberID (%s) or "
//                            + "groupID (%s).", groupMemberID, groupID);
//            processError(e, Status.CLIENT_ERROR_BAD_REQUEST, message);
//        }
        catch (URISyntaxException e)
        {
            final String message = "Client encoding not supported in delete";
            processError(e, Status.CLIENT_ERROR_BAD_REQUEST, message);
        }
        return false;
    }

    /**
     * Assemble the XML for this Resource's Representation into the given
     * Document.
     * 
     * @param document
     *            The Document to build up.
     * @throws java.io.IOException
     *             If something went wrong or the XML cannot be built.
     */
    protected void buildXML(final Document document) throws IOException
    {
        LOGGER.debug("Enter GroupMemberResource.buildXML()");
        document.addContent(GroupWriter.getGroupElement(group));
    }

    /**
     * Accept a POST to this Resource to Update a Group.
     *
     * @param entity        The Request payload.
     */
    @Post
    public void acceptPost(final Representation entity)
    {
        try
        {
//            String groupID = URLDecoder.decode(getGroupID(), "UTF-8");
            String groupID = getGroupID();
            LOGGER.debug("Create a new group with ID." + groupID);

            final Group postedGroup = GroupReader.read(entity.getStream());
            group = getGroupService().postGroup(postedGroup);
            LOGGER.debug(String.format("Created groupID: %s", group
                    .getID()));
            setLocationRef(group.getID().toString());
            setStatus(Status.SUCCESS_CREATED);
        }
        catch (AuthorizationException e)
        {
            final String message = "You are not authorized to create new groups.";
            processError(e, Status.CLIENT_ERROR_UNAUTHORIZED, message);
        }
        catch (InvalidGroupException e)
        {
            // this should not happen for a null group id
            final String message = "Creation of new groups not supported";
            processError(e, Status.CLIENT_ERROR_BAD_REQUEST, message);
        }
        catch (UnsupportedEncodingException e)
        {
            final String message = String.format(
                    "Could not URL decode groupID (%s).", getGroupID());
            processError(e, Status.CLIENT_ERROR_BAD_REQUEST, message);
        }
        catch (URISyntaxException e)
        {
            final String message = "Client encoding not supported in delete";
            processError(e, Status.CLIENT_ERROR_BAD_REQUEST, message);
        }
        catch (ReaderException e)
        {
            final String message = "Unable to read POSTed Group.";
            processError(e, Status.CLIENT_ERROR_BAD_REQUEST, message);
        }
        catch (IOException e)
        {
            final String message = "BUG *** Bad error with I/O";
            processError(e, Status.CLIENT_ERROR_BAD_REQUEST, message);
        }
    }

    /**
     * Accept a PUT to this Resource to Create a Group.
     *
     * @param entity        The Request payload.
     */
    @Put
    public void acceptPut(final Representation entity)
    {
        processNotImplemented(String
                .format("The Service to create Group with "
                        + "ID '%s' is not yet implemented.", getGroupID()));
    }

    /**
     * Accept a DELETE to this Resource to Delete a Group.
     */
    @Delete
    public void acceptDelete()
    {
        LOGGER.debug("Delete group.");
        try
        {
//            String groupID = URLDecoder.decode(getGroupID(), "UTF-8");
            final String groupID = getGroupID();
            LOGGER.debug(String.format("groupID: %s", groupID));

            getGroupService().deleteGroup(
                    new URI(groupService.getGroupUriPrefix() + groupID));
            LOGGER.debug(String.format("Deleted groupID: %s", groupID));
        }
        catch (AuthorizationException e)
        {
            final String message = "You are not authorized to delete groups.";
            processError(e, Status.CLIENT_ERROR_UNAUTHORIZED, message);
        }
        catch (InvalidGroupException e)
        {
            // this should not happen for a null group id
            final String message = "Deletion of new groups not supported";
            processError(e, Status.CLIENT_ERROR_BAD_REQUEST, message);
        }
//        catch (UnsupportedEncodingException e)
//        {
//            final String message = "Client encoding not supported in delete";
//            processError(e, Status.CLIENT_ERROR_BAD_REQUEST, message);
//        }
        catch (URISyntaxException e)
        {
            final String message = "Client encoding not supported in delete";
            processError(e, Status.CLIENT_ERROR_BAD_REQUEST, message);
        }
    }

    protected Group getGroup() throws AuthorizationException,
            InvalidGroupException, URISyntaxException
    {
        return getGroupService().getGroup(
                new URI(groupService.getGroupUriPrefix() + getGroupID()));
    }

    protected String getGroupID()
    {
        return (String) getRequestAttribute("groupID");
    }

    public GroupService getGroupService()
    {
        return groupService;
    }

    public void setGroupService(final GroupService groupService)
    {
        this.groupService = groupService;
    }
}
