/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2009.                            (c) 2009.
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
*  $Revision: 4 $
*
************************************************************************
*/

/**
 * 
 */
package ca.nrc.cadc.tap.parser;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ca.nrc.cadc.tap.AdqlQuery;
import ca.nrc.cadc.tap.TapQuery;
import ca.nrc.cadc.tap.parser.extractor.SelectListExtractor;
import ca.nrc.cadc.tap.parser.navigator.FromItemNavigator;
import ca.nrc.cadc.tap.parser.navigator.ReferenceNavigator;
import ca.nrc.cadc.tap.parser.navigator.SelectNavigator;
import ca.nrc.cadc.tap.parser.region.pgsphere.PgsphereRegionConverter;
import ca.nrc.cadc.tap.schema.TapSchema;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.uws.Parameter;

/**
 * 
 * @author Sailor Zhang
 *
 */
public class PgsRegionConverterTest
{
    public String _query;
    public String _expected = "";
    
    

    SelectListExtractor _en;
    ReferenceNavigator _rn;
    FromItemNavigator _fn;
    SelectNavigator _sn;

    static TapSchema TAP_SCHEMA;

    /**
     * @throws java.lang.Exception
     */
    @BeforeClass
    public static void setUpBeforeClass() throws Exception
    {
        Log4jInit.setLevel("ca.nrc.cadc", org.apache.log4j.Level.WARN);
        TAP_SCHEMA = TestUtil.loadDefaultTapSchema();
    }

    /**
     * @throws java.lang.Exception
     */
    @AfterClass
    public static void tearDownAfterClass() throws Exception
    {
    }

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception
    {
    }

    /**
     * @throws java.lang.Exception
     */
    @After
    public void tearDown() throws Exception
    {
    }

    private void doit()
    {
        Parameter para;
        para = new Parameter("QUERY", _query);
        List<Parameter> paramList = new ArrayList<Parameter>();
        paramList.add(para);

        TapQuery tapQuery = new AdqlPgsRegionQuery(); // inner class in this file
        tapQuery.setTapSchema(TAP_SCHEMA);
        tapQuery.setExtraTables(null);
        tapQuery.setParameterList(paramList);
        String sql = tapQuery.getSQL();
        System.out.println(_query);
        System.out.println(_expected);
        System.out.println(sql);
        assertEquals(_expected.toLowerCase(), sql.toLowerCase());
    }

    //@Test
    public void testAll()
    {
        _query = "select COORDSYS(a.t_box), COORD1(a.t_spoint), COORD2(a.t_spoint) from TAP_SCHEMA.AllDataTypes a"
                + " where 0 = CONTAINS(POINT('ICRS GEOCENTER', 25.0, -19.5), POLYGON('ICRS GEOCENTER', 12, 44.0, 7.6, -19.5, a.t_long, a.t_double)) "
                + "    and INTERSECTS(a.t_scircle, CIRCLE('ICRS GEOCENTER', 44.0, -7.6, 19.5))=1 ";
        _expected = "SELECT 'ICRS GEOCENTER', long(a.t_spoint), lat(a.t_spoint) FROM TAP_SCHEMA.AllDataTypes AS a WHERE spoint '( 25.0d, -19.5d)' !@ spoly '{(12d, 44.0d), (7.6d, -19.5d), (a.t_long, a.t_double) }' AND a.t_scircle && scircle '< (44.0d, -7.6d), 19.5d>'"; 
            
        doit();
    }

    //@Test
    public void testNone()
    {
        _query = "select a.t_box, a.t_spoint, a.t_spoint from TAP_SCHEMA.AllDataTypes a" + " where a.t_long = 1";
        _expected = "select a.t_box, a.t_spoint, a.t_spoint from tap_schema.alldatatypes as a where a.t_long = 1";
        doit();
    }

    @Test
    public void testJoin()
    {
        
        _query = "select a.t_box, b.t_spoint from tap_schema.alldatatypes as a join tap_schema.alldatatypes as b on (INTERSECTS(a.t_scircle, b.t_box)=1)";
        _expected = "select a.t_box, b.t_spoint from tap_schema.alldatatypes as a join tap_schema.alldatatypes as b on (a.t_scircle && b.t_box)";
        doit();
    }
}

class AdqlPgsRegionQuery extends AdqlQuery
{
    protected void init()
    {
        super.init();
        _navigatorList.add(new PgsphereRegionConverter());
    }
}