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

package ca.nrc.cadc.tap.parser.finder;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.management.RuntimeErrorException;

import net.sf.jsqlparser.schema.Column;
import net.sf.jsqlparser.schema.Table;
import net.sf.jsqlparser.statement.select.ColumnReference;
import net.sf.jsqlparser.statement.select.Distinct;
import net.sf.jsqlparser.statement.select.FromItem;
import net.sf.jsqlparser.statement.select.FromItemVisitor;
import net.sf.jsqlparser.statement.select.Join;
import net.sf.jsqlparser.statement.select.Limit;
import net.sf.jsqlparser.statement.select.OrderByElement;
import net.sf.jsqlparser.statement.select.PlainSelect;
import net.sf.jsqlparser.statement.select.SelectItem;
import net.sf.jsqlparser.statement.select.SelectItemVisitor;
import net.sf.jsqlparser.statement.select.SelectVisitor;
import net.sf.jsqlparser.statement.select.SubSelect;
import net.sf.jsqlparser.statement.select.Top;
import net.sf.jsqlparser.statement.select.Union;

import org.apache.log4j.Logger;

import ca.nrc.cadc.tap.parser.adql.AdqlManager;
import ca.nrc.cadc.tap.parser.adql.exception.AdqlValidateException;
import ca.nrc.cadc.tap.parser.adql.validator.AdqlValidatorVisitor;
import ca.nrc.cadc.tap.parser.adql.validator.PlainSelectInfo;
import ca.nrc.cadc.tap.parser.adql.validator.SelectValidator;
import ca.nrc.cadc.tap.parser.adql.validator.SelectValidator.PlainSelectType;
import ca.nrc.cadc.tap.parser.adql.validator.SelectValidator.VisitingPart;
import ca.nrc.cadc.tap.parser.navigator.ExpressionNavigator;
import ca.nrc.cadc.tap.parser.navigator.FromItemNavigator;
import ca.nrc.cadc.tap.parser.navigator.ReferenceNavigator;
import ca.nrc.cadc.tap.parser.navigator.SelectNavigator;

/**
 * Basic SelectVisitor implementation. This class implements FromItemVisitor to handle references to tables and subselects in a
 * simple fashion. It implements SelectItemVisitor in order to process the expressions in the select list itself.
 * 
 * 
 * @author pdowler, Sailor Zhang
 */
// Prototype: AdqlSelectVisitorProto
public class SelectFinder extends SelectNavigator 
{
    protected static Logger log = Logger.getLogger(SelectFinder.class);

    public void visit(PlainSelect plainSelect)
    {
        log.debug("visit(PlainSelect) " + plainSelect);
        enterPlainSelect(plainSelect);

        this._visitingPart = VisitingPart.FROM;
        FromItem fromItem = _plainSelect.getFromItem();
        if (fromItem instanceof Table)
            fromItem.accept(_fromItemNavigator);
        else if (fromItem instanceof SubSelect)
            throw new UnsupportedOperationException("sub-select not supported in FROM clause.");

        if (isToStop())
            return;

        NavigateJoins();
        if (isToStop())
            return;

        this._visitingPart = VisitingPart.SELECT_ITEM;
        List<SelectItem> selectItems = _plainSelect.getSelectItems();
        if (selectItems != null)
            for (SelectItem s : selectItems)
                s.accept(this._expressionNavigator);

        this._visitingPart = VisitingPart.WHERE;
        if (_plainSelect.getWhere() != null)
            _plainSelect.getWhere().accept(_expressionNavigator);

        this._visitingPart = VisitingPart.GROUP_BY;
        List<ColumnReference> crs = _plainSelect.getGroupByColumnReferences();
        if (crs != null)
            for (ColumnReference cr : crs)
                cr.accept(_referenceNavigator);

        this._visitingPart = VisitingPart.ORDER_BY;
        List<OrderByElement> obes = _plainSelect.getOrderByElements();
        if (obes != null)
        {
            for (OrderByElement obe : obes)
            {
                ColumnReference cr = obe.getColumnReference();
                if (cr != null)
                    cr.accept(_referenceNavigator);
            }
        }

        this._visitingPart = VisitingPart.HAVING;
        if (_plainSelect.getHaving() != null)
            _plainSelect.getHaving().accept(_expressionNavigator);

        // other SELECT options
        if (_plainSelect.getLimit() != null)
            handleLimit(_plainSelect.getLimit());
        if (_plainSelect.getDistinct() != null)
            handleDistinct(_plainSelect.getDistinct());
        if (_plainSelect.getInto() != null)
            handleInto(_plainSelect.getInto());
        if (_plainSelect.getTop() != null)
            handleTop(_plainSelect.getTop());

        log.debug("visit(PlainSelect) done");
        leavePlainSelect();
    }


    /*
     * Setters and Getters -------------------------------------------------
     */


    public boolean isToStop()
    {
        return toStop;
    }

    public void setToStop(boolean toStop)
    {
        this.toStop = toStop;
    }

    /**
     * Handle use of the TOP construct. The implementation logs.
     */
    protected void handleTop(Top top)
    {
        log.debug("handleTop: " + top);
    }

    /**
     * Handle use of the LIMIT construct. The implementation logs.
     */
    protected void handleLimit(Limit limit)
    {
        log.debug("handleLimit: " + limit);
    }

    /**
     * Handle use of the DISTINCT construct. The implementation logs and visits explicit expressions (itself) in the optional
     * ON(...) since they are not part of the select list.
     */
    protected void handleDistinct(Distinct distinct)
    {
        log.debug("handleDistinct: " + distinct);
        List<SelectItem> onSelectItems = distinct.getOnSelectItems(); 
        if ( onSelectItems != null)
            for (SelectItem si : onSelectItems) {
                if (si != null)
                    si.accept(_expressionNavigator);
            }
    }

    /**
     * Handle use of SELECT INTO. The implementation logs and throws an Exception.
     */
    protected void handleInto(Table dest)
    {
        log.debug("handleInto: " + dest);
        throw new UnsupportedOperationException("SELECT INTO is not supported.");
    }

    public PlainSelect getPlainSelect()
    {
        return _plainSelect;
    }

    public void setPlainSelect(PlainSelect plainSelect)
    {
        _plainSelect = plainSelect;
    }
}
