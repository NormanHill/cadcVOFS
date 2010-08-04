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
package ca.nrc.cadc.gms.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.Collection;

import org.junit.Test;

import ca.nrc.cadc.gms.GMSTest;
import ca.nrc.cadc.gms.Group;
import ca.nrc.cadc.gms.InvalidGroupException;
import ca.nrc.cadc.gms.InvalidMemberException;
import ca.nrc.cadc.gms.User;


/**
 * Unit test for the UserService interface's implementations.
 */
public abstract class UserServiceTest extends GMSTest<UserService>
{
    protected final static String NO_MEMBERSHIP_GROUP_ID = Long.toString(999l);
    protected final static String GROUP_ID = Long.toString(888l);
    protected final static String NON_GROUP_ID = Long.toString(-888l);
    protected final static String MEMBER_USER_ID = Long.toString(88l);
    protected final static String NON_MEMBER_USER_ID = Long.toString(-88l);


    @Test
    public void getMemberships() throws Exception
    {
        final Collection<Group> memberships =
                getTestSubject().getMemberships(MEMBER_USER_ID);
        assertNotNull("Group Collection may never be null.", memberships);
        assertEquals("Group should have a single member.", 1,
                     memberships.size());
        assertEquals("Group should be the 888 Group.", GROUP_ID, 
                   ((Group) memberships.toArray()[0]).getGMSGroupID());

        try
        {
            getTestSubject().getMemberships(NON_MEMBER_USER_ID);
            fail("Non member ID found!");
        }
        catch (InvalidMemberException ime)
        {
            // Good!
        }
    }

    @Test
    public void getMember() throws Exception
    {
        final User member =
                getTestSubject().getMember(MEMBER_USER_ID, GROUP_ID);

        assertNotNull("The member returned should be valid.", member);
        assertEquals("The member is the wrong one.", MEMBER_USER_ID,
                     member.getUserID());

        try
        {
            getTestSubject().getMember(MEMBER_USER_ID, NO_MEMBERSHIP_GROUP_ID);
            fail("The User with this MEMBER_USER_ID is not a member.");
        }
        catch (IllegalArgumentException iae)
        {
            // Good!
        }

        try
        {
            getTestSubject().getMember(NON_MEMBER_USER_ID, GROUP_ID);
            fail("This member is not a member.");
        }
        catch (InvalidMemberException ime)
        {
            // Good!
        }

        try
        {
            getTestSubject().getMember(MEMBER_USER_ID, NON_GROUP_ID);
            fail("This Group is not a Group.");
        }
        catch (InvalidGroupException ige)
        {
            // Good!
        }
    }
}
