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

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package ca.nrc.cadc.tap.parser.adql.impl.postgresql.sql;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 
 * @author pdowler
 * @author Sailor Zhang
 */
public class Constants
{
    // ADQL region functions
    public static String CONTAINS = "CONTAINS";
    public static String INTERSECTS = "INTERSECTS";
    public static String POINT = "POINT";
    public static String CIRCLE = "CIRCLE";
    public static String POLYGON = "POLYGON";
    public static String REGION = "REGION";
    public static String AREA = "AREA";
    public static String CENTROID = "CENTROID";
    public static String COORDSYS = "COORDSYS";
    public static String CVAL1 = "CVAL1";
    public static String CVAL2 = "CVAL2";

    public static List<String> REGION_SCALAR_FUNCTIONS; // functions that extract scalars from regions
    public static List<String> REGION_PREDICATES; // functions that compare regions
    public static List<String> REGION_GEOM_FUNCTIONS; // functions that create/return regions

    public static List<String> REGION_FUNCTIONS;

    public static List<String> MATH_FUNCTIONS;

    public static List<String> AGGREGATE_FUNCTIONS;

    static
    {
        REGION_PREDICATES = Arrays.asList(new String[] { CONTAINS, INTERSECTS });
        REGION_GEOM_FUNCTIONS = Arrays.asList(new String[] { POINT, CIRCLE, POLYGON, CENTROID, REGION, });
        REGION_SCALAR_FUNCTIONS = Arrays.asList(new String[] { AREA, COORDSYS, CVAL1, CVAL2 });

        REGION_FUNCTIONS = new ArrayList<String>();
        REGION_FUNCTIONS.addAll(REGION_PREDICATES);
        REGION_FUNCTIONS.addAll(REGION_GEOM_FUNCTIONS);
        REGION_FUNCTIONS.addAll(REGION_SCALAR_FUNCTIONS);

        MATH_FUNCTIONS = Arrays.asList(new String[] { "ACOS", "ASIN", "ATAN", "ATAN2", "COS", "SIN", "TAN", "ABS", "CEILING",
                "DEGREES", "EXP", "FLOOR", "LOG", "LOG10", "MOD", "PI", "POWER", "RADIANS", "SQRT", "RAND", "ROUND", "TRUNCATE" });

        AGGREGATE_FUNCTIONS = Arrays.asList(new String[] { "COUNT", "MIN", "MAX" });
    }
}
