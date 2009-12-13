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

package ca.nrc.cadc.tap.parser.adql.validator;

import java.util.ArrayList;
import java.util.List;

import net.sf.jsqlparser.schema.Column;
import net.sf.jsqlparser.schema.Table;
import net.sf.jsqlparser.statement.select.PlainSelect;
import net.sf.jsqlparser.statement.select.SelectExpressionItem;
import net.sf.jsqlparser.statement.select.SelectItem;
import net.sf.jsqlparser.statement.select.SubSelect;
import ca.nrc.cadc.tap.parser.TapSelectItem;
import ca.nrc.cadc.tap.parser.adql.config.AdqlConfig;
import ca.nrc.cadc.tap.parser.adql.config.meta.ColumnMeta;
import ca.nrc.cadc.tap.parser.adql.config.meta.TableMeta;
import ca.nrc.cadc.tap.parser.adql.exception.AdqlValidateException;

/**
 * Stores information of a plain select:
 * 
 * <li>a complete list of all columns, including normal columns, columns in sub-select, and generated columns.
 * 
 * @author zhangsa
 * 
 */
public class PlainSelectInfo
{

    protected List<FromColumn> _fromColumns = new ArrayList<FromColumn>();
    protected List<TapSelectItem> _tapSelectItems = new ArrayList<TapSelectItem>();

    public int countFromColumnsMatches(Column c1)
    {
        int count = 0;
        for (FromColumn fromColumn : this._fromColumns)
        {
            if (fromColumn.matches(c1))
                count++;
        }
        return count;
    }

    public FromColumn findFirstFromColumnMatch(Column c1)
    {
        FromColumn rtn = null;
        for (FromColumn fromColumn : this._fromColumns)
        {
            if (fromColumn.matches(c1))
            {
                rtn = fromColumn;
                break;
            }
        }
        return rtn;
    }

    public void addFromTable(Table table, AdqlConfig config) throws AdqlValidateException
    {
        TableMeta tableMeta = config.findTableMeta(table);
        if (tableMeta == null)
            throw new AdqlValidateException(table.getWholeTableName() + " is invalid.");
        FromColumn fromColumn;
        String tableAlias = table.getAlias();
        String schemaName = tableMeta.getSchemaName();
        String tableName = tableMeta.getTableName();
        String columnName;
        String columnAlias = null;
        for (ColumnMeta cm : tableMeta.getColumnMetas())
        {
            columnName = cm.getName();
            fromColumn = new FromColumn(tableAlias, schemaName, tableName, columnName, columnAlias);
            this._fromColumns.add(fromColumn);
        }
    }

    public void addFromSubSelect(SubSelect subSelect, AdqlConfig config) throws AdqlValidateException
    {
        FromColumn fromColumn;
        String tableAlias = subSelect.getAlias();
        String schemaName = null;
        String tableName = null;
        String columnName = null;
        String columnAlias = null;

        if (subSelect.getSelectBody() instanceof PlainSelect)
        {
            PlainSelect plainSelect = (PlainSelect) subSelect.getSelectBody();
            for (SelectItem selectItem : (List<SelectItem>) plainSelect.getSelectItems())
            {
                columnName = null;
                columnAlias = null;
                if (selectItem instanceof SelectExpressionItem)
                {
                    SelectExpressionItem sei = (SelectExpressionItem) selectItem;
                    columnAlias = sei.getAlias();
                    if (sei.getExpression() instanceof Column)
                    {
                        columnName = ((Column) sei.getExpression()).getColumnName();
                    }
                } else
                {
                    throw new AdqlValidateException("Invalid SubSelect");
                }
                fromColumn = new FromColumn(tableAlias, schemaName, tableName, columnName, columnAlias);
                this._fromColumns.add(fromColumn);
            }
        }
    }

    public List<TapSelectItem> getTapSelectItems()
    {
        return _tapSelectItems;
    }

    public List<FromColumn> getFromColumns()
    {
        return _fromColumns;
    }

    public void addTapSelectItem(TapSelectItem tapSelectItem)
    {
        _tapSelectItems.add(tapSelectItem);
    }
}
