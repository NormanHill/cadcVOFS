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
package ca.nrc.cadc.tap.parser.adql.impl.postgresql.pgsphere;

import ca.nrc.cadc.tap.parser.adql.config.AdqlConfig;
import ca.nrc.cadc.tap.parser.adql.config.meta.ColumnMeta;
import ca.nrc.cadc.tap.parser.adql.config.meta.FunctionMeta;
import ca.nrc.cadc.tap.parser.adql.config.meta.TableMeta;

/**
 * @author zhangsa
 * 
 */
public class AdqlConfigImpl extends AdqlConfig
{

    public AdqlConfigImpl()
    {
        super();
        configName = "CADC PostgreSQL pgSphere 1.1";
        initFunctionMeta();
        initTableMeta();

        allowJoins = true; // Allow multiple tables in FROM clause (including JOIN). Default: true.
        allowUnion = true; // Allow UNION. Default: true.
        allowGroupBy = true; // Allow GROUP BY. Default: true.
        allowOrderBy = true; // Allow ORDER BY. Default: true.
        allowLimit = false; // Allow LIMIT. Default: false (not an ADQL construct)
        allowTop = true; // Allow TOP. Default: true.
        allowDistinct = true; // Allow DISTINCT. Default: true.
        allowInto = false; // Allow SELECT INTO. Default: false (not an ADQL construct)
        // caseSensitive = false; // Whether column, table, and schema names are case sensitive. -sz 2009-09-10

    }

    private void initFunctionMeta()
    {
        functionMetas.add(new FunctionMeta(Constants.AREA));
        // functions.add(new FunctionMeta(Constants.CENTROID));
        functionMetas.add(new FunctionMeta(Constants.CIRCLE));
        functionMetas.add(new FunctionMeta(Constants.CONTAINS));
        functionMetas.add(new FunctionMeta(Constants.COORDSYS));
        // functions.add(new FunctionMeta(Constants.CVAL1));
        // functions.add(new FunctionMeta(Constants.CVAL2));
        functionMetas.add(new FunctionMeta(Constants.INTERSECTS));
        functionMetas.add(new FunctionMeta(Constants.POINT));
        functionMetas.add(new FunctionMeta(Constants.POLYGON));
        // functions.add(new FunctionMeta(Constants.REGION));

        for (int i = 0; i < Constants.AGGREGATE_FUNCTIONS.size(); i++)
            functionMetas.add(new FunctionMeta((String) Constants.AGGREGATE_FUNCTIONS.get(i)));

        for (int i = 0; i < Constants.MATH_FUNCTIONS.size(); i++)
            functionMetas.add(new FunctionMeta((String) Constants.MATH_FUNCTIONS.get(i)));
    }

    private void initTableMeta()
    {
        TableMeta tab;

        tab = new TableMeta("observation", "plane");
        tab.addColumnMeta(new ColumnMeta("obsID", "int", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("collection", "string", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("collectionID", "string", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("project", "string", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("instrument", "string", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("shape", "polygon", "TODO", "deg"));
        tableMetas.add(tab);

        tab = new TableMeta("observation2", "plane");
        tab.addColumnMeta(new ColumnMeta("obsID", "int", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("collection", "string", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("collectionID", "string", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("project", "string", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("instrument", "string", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("shape", "polygon", "TODO", "deg"));
        tableMetas.add(tab);

        tab = new TableMeta("observation", "spatial");
        tab.addColumnMeta(new ColumnMeta("obsID", "int", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("ctype1", "string", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("ctype2", "string", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("naxis1", "int", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("naxis2", "int", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("crpix1", "double", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("crpix2", "double", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("crval1", "double", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("crval2", "double", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("cd1_1", "double", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("cd1_2", "double", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("cd2_1", "double", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("cd2_2", "double", "TODO", null));
        tableMetas.add(tab);

        tab = new TableMeta("observation", "spectral");
        tab.addColumnMeta(new ColumnMeta("obsID", "int", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("filter_id", "string", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("filter_lo", "double", "TODO", "m"));
        tab.addColumnMeta(new ColumnMeta("filter_hi", "double", "TODO", "m"));
        tableMetas.add(tab);

        tab = new TableMeta("observation", "temporal");
        tab.addColumnMeta(new ColumnMeta("obsID", "int", "TODO", null));
        tab.addColumnMeta(new ColumnMeta("mjdate_lo", "double", "TODO", "d"));
        tab.addColumnMeta(new ColumnMeta("mjdate_hi", "double", "TODO", "d"));
        tab.addColumnMeta(new ColumnMeta("exptime", "double", "TODO", "sec"));
        tableMetas.add(tab);
    }
}
