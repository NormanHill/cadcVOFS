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
package ca.nrc.cadc.gms.web.resources.restlet;

import org.junit.Test;
import static org.easymock.EasyMock.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import ca.nrc.cadc.gms.service.UserService;
import ca.nrc.cadc.gms.service.GroupService;
import ca.nrc.cadc.gms.web.xml.UserXMLWriter;
import ca.nrc.cadc.gms.User;

import java.io.OutputStream;
import java.io.ByteArrayOutputStream;


public class GroupMemberResourceTest
        extends AbstractResourceTest<GroupMemberResource>
{
    private GroupService mockGroupService;
    private UserService mockUserService;
    private UserXMLWriter mockUserWriter;
    private OutputStream outputStream = new ByteArrayOutputStream(256);
    private Document mockParsedDocument;


    /**
     * Prepare the testSubject to be tested.
     *
     * @throws Exception For anything that went wrong.
     */
    public void initializeTestSubject() throws Exception
    {
        setMockGroupService(createMock(GroupService.class));
        setMockUserService(createMock(UserService.class));
        setMockUserWriter(createMock(UserXMLWriter.class));
        mockParsedDocument = createMock(Document.class);

        setTestSubject(new GroupMemberResource(getMockGroupService(),
                                               getMockUserService())
        {
            @Override
            protected String getGroupID()
            {
                return Long.toString(88l);
            }

            @Override
            protected String getMemberID()
            {
                return Long.toString(88l);
            }

            /**
             * Parse a Document from the given String.
             *
             * @param writtenData The String data.
             * @return The Document object.
             */
            @Override
            protected Document parseDocument(final String writtenData)
            {
                return mockParsedDocument;
            }

            /**
             * Create a new instance of a UserXMLWriter implementation.
             *
             * @param outputStream The OutputStream to write out the data.
             * @param member       The member to create it with.
             * @return An instance of an UserXMLWriter implementation.
             *         <p/>
             */
            @Override
            protected UserXMLWriter createMemberXMLWriter(
                    final OutputStream outputStream, final User member)
            {
                return getMockUserWriter();
            }

            /**
             * Obtain an OutputStream to write to.  This can be overridden.
             *
             * @return An OutputStream instance.
             */
            @Override
            protected OutputStream getOutputStream()
            {
                return outputStream;
            }
        });
    }

    @Test
    public void buildXMLMember() throws Exception
    {
        final StringBuilder xml = new StringBuilder(128);
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n");
        xml.append("<member id=\"88\">\n");
        xml.append("  <username>TESTUSERNAME</username>\n");
        xml.append("</member>");

        outputStream.write(xml.toString().getBytes());

        final User mockUser = createMock(User.class);
        final Document mockDocument = createMock(Document.class);
        final Element mockParsedDocumentElement = createMock(Element.class);

        expect(mockUser.getUserID()).andReturn(Long.toString(88l)).once();
        expect(mockUser.getUsername()).andReturn("TESTUSERNAME").once();
        
        getMockUserWriter().write();
        expectLastCall().once();

        expect(mockParsedDocument.getDocumentElement()).
                andReturn(mockParsedDocumentElement).once();
        expect(mockDocument.importNode(mockParsedDocumentElement, true)).
                andReturn(mockParsedDocumentElement).once();
        expect(mockDocument.appendChild(mockParsedDocumentElement)).
                andReturn(mockParsedDocumentElement).once();

        expect(getMockUserService().getMember(Long.toString(88l),
                                              Long.toString(88l))).
                andReturn(mockUser).once();
        expect(getMockUserService().getUser(Long.toString(88l))).
                andReturn(mockUser).once();

        replay(mockUser, mockDocument, mockParsedDocument,
               mockParsedDocumentElement, getMockUserService(),
               getMockUserWriter(), getMockGroupService());

        getTestSubject().buildXML(mockDocument);
    }

    public GroupService getMockGroupService()
    {
        return mockGroupService;
    }

    public void setMockGroupService(GroupService mockGroupService)
    {
        this.mockGroupService = mockGroupService;
    }

    public UserService getMockUserService()
    {
        return mockUserService;
    }

    public void setMockUserService(UserService mockUserService)
    {
        this.mockUserService = mockUserService;
    }

    public UserXMLWriter getMockUserWriter()
    {
        return mockUserWriter;
    }

    public void setMockUserWriter(UserXMLWriter mockUserWriter)
    {
        this.mockUserWriter = mockUserWriter;
    }
}
