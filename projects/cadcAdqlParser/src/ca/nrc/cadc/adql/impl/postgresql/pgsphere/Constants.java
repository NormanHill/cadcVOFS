/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÃES ASTRONOMIQUES  **************
*
*  (c) 2009.                            (c) 2009.
*  Government of Canada                 Gouvernement du Canada
*  National Research Council            Conseil national de recherches
*  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
*  All rights reserved                  Tous droits rÃ©servÃ©s
*                                       
*  NRC disclaims any warranties,        Le CNRC dÃ©nie toute garantie
*  expressed, implied, or               Ã©noncÃ©e, implicite ou lÃ©gale,
*  statutory, of any kind with          de quelque nature que ce
*  respect to the software,             soit, concernant le logiciel,
*  including without limitation         y compris sans restriction
*  any warranty of merchantability      toute garantie de valeur
*  or fitness for a particular          marchande ou de pertinence
*  purpose. NRC shall not be            pour un usage particulier.
*  liable in any event for any          Le CNRC ne pourra en aucun cas
*  damages, whether direct or           Ãªtre tenu responsable de tout
*  indirect, special or general,        dommage, direct ou indirect,
*  consequential or incidental,         particulier ou gÃ©nÃ©ral,
*  arising from the use of the          accessoire ou fortuit, rÃ©sultant
*  software.  Neither the name          de l'utilisation du logiciel. Ni
*  of the National Research             le nom du Conseil National de
*  Council of Canada nor the            Recherches du Canada ni les noms
*  names of its contributors may        de ses  participants ne peuvent
*  be used to endorse or promote        Ãªtre utilisÃ©s pour approuver ou
*  products derived from this           promouvoir les produits dÃ©rivÃ©s
*  software without specific prior      de ce logiciel sans autorisation
*  written permission.                  prÃ©alable et particuliÃ¨re
*                                       par Ã©crit.
*                                       
*  This file is part of the             Ce fichier fait partie du projet
*  OpenCADC project.                    OpenCADC.
*                                       
*  OpenCADC is free software:           OpenCADC est un logiciel libre ;
*  you can redistribute it and/or       vous pouvez le redistribuer ou le
*  modify it under the terms of         modifier suivant les termes de
*  the GNU Affero General Public        la âGNU Affero General Public
*  License as published by the          Licenseâ telle que publiÃ©e
*  Free Software Foundation,            par la Free Software Foundation
*  either version 3 of the              : soit la version 3 de cette
*  License, or (at your option)         licence, soit (Ã  votre grÃ©)
*  any later version.                   toute version ultÃ©rieure.
*                                       
*  OpenCADC is distributed in the       OpenCADC est distribuÃ©
*  hope that it will be useful,         dans lâespoir quâil vous
*  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
*  without even the implied             GARANTIE : sans mÃªme la garantie
*  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÃ
*  or FITNESS FOR A PARTICULAR          ni dâADÃQUATION Ã UN OBJECTIF
*  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
*  General Public License for           GÃ©nÃ©rale Publique GNU Affero
*  more details.                        pour plus de dÃ©tails.
*                                       
*  You should have received             Vous devriez avoir reÃ§u une
*  a copy of the GNU Affero             copie de la Licence GÃ©nÃ©rale
*  General Public License along         Publique GNU Affero avec
*  with OpenCADC.  If not, see          OpenCADC ; si ce nâest
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

package ca.nrc.cadc.adql.impl.postgresql.pgsphere;

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
    public static String CONTAINS   = "CONTAINS";
    public static String INTERSECTS = "INTERSECTS";
    public static String POINT      = "POINT";
    public static String CIRCLE     = "CIRCLE";
    public static String POLYGON    = "POLYGON";
    public static String REGION     = "REGION";
    public static String AREA       = "AREA";
    public static String CENTROID   = "CENTROID";
    public static String COORDSYS   = "COORDSYS";
    public static String CVAL1      = "CVAL1";
    public static String CVAL2      = "CVAL2";
    
    public static List<String> REGION_SCALAR_FUNCTIONS; // functions that extract scalars from regions
    public static List<String> REGION_PREDICATES; // functions that compare regions
    public static List<String> REGION_GEOM_FUNCTIONS; // functions that create/return regions

    public static List<String> REGION_FUNCTIONS;
    
    public static List<String> MATH_FUNCTIONS;
    
    public static List<String> AGGREGATE_FUNCTIONS;

    static
    {
        REGION_PREDICATES = Arrays.asList(new String[]
            {
                CONTAINS, INTERSECTS
            });
        REGION_GEOM_FUNCTIONS = Arrays.asList(new String[]
            {
                POINT, CIRCLE, POLYGON, CENTROID, REGION, 
            });
        REGION_SCALAR_FUNCTIONS = Arrays.asList(new String[]
            {
                AREA, COORDSYS, CVAL1, CVAL2
            });
        
        REGION_FUNCTIONS = new ArrayList<String>();
        REGION_FUNCTIONS.addAll(REGION_PREDICATES);
        REGION_FUNCTIONS.addAll(REGION_GEOM_FUNCTIONS);
        REGION_FUNCTIONS.addAll(REGION_SCALAR_FUNCTIONS);
        
        MATH_FUNCTIONS = Arrays.asList(new String[]
        {
            "ACOS", "ASIN", "ATAN", "ATAN2", "COS", "SIN", "TAN",
            "ABS", "CEILING", "DEGREES", "EXP", "FLOOR", 
            "LOG", "LOG10", "MOD", "PI", "POWER", "RADIANS",
            "SQRT", "RAND", "ROUND", "TRUNCATE"
        });
        
        AGGREGATE_FUNCTIONS = Arrays.asList(new String[]
        {
            "COUNT", "MIN", "MAX"
        });
    }
}
