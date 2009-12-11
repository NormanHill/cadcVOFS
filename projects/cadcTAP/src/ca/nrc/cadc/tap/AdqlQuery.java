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

package ca.nrc.cadc.tap;

import ca.nrc.cadc.tap.schema.TableDesc;

import java.util.ArrayList;
import java.util.List;

import ca.nrc.cadc.tap.parser.ParserUtil;
import ca.nrc.cadc.tap.parser.adql.AdqlManager;
import ca.nrc.cadc.tap.parser.adql.AdqlParser;
import ca.nrc.cadc.tap.parser.adql.TapSelectItem;
import ca.nrc.cadc.tap.parser.adql.exception.AdqlException;
import ca.nrc.cadc.tap.parser.converter.basic.AllColumnConverterNavigator;
import ca.nrc.cadc.tap.parser.extractor.SelectListExtractor;
import ca.nrc.cadc.tap.parser.extractor.SelectListExtractorNavigator;
import ca.nrc.cadc.tap.parser.navigator.ExpressionNavigator;
import ca.nrc.cadc.tap.parser.navigator.FromItemNavigator;
import ca.nrc.cadc.tap.parser.navigator.ReferenceNavigator;
import ca.nrc.cadc.tap.parser.navigator.SelectNavigator;
import ca.nrc.cadc.tap.parser.validator.ExpressionValidator;
import ca.nrc.cadc.tap.parser.validator.FromItemValidator;
import ca.nrc.cadc.tap.parser.validator.ReferenceValidator;
import ca.nrc.cadc.tap.parser.validator.ValidatorNavigator;
import ca.nrc.cadc.tap.schema.TapSchema;
import ca.nrc.cadc.uws.Parameter;
import java.util.Map;

import org.apache.log4j.Logger;

import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.statement.Statement;

/**
 * TapQuery implementation for LANG=ADQL.
 */
public class AdqlQuery implements TapQuery
{
    protected static Logger log = Logger.getLogger(AdqlQuery.class);

    protected TapSchema _tapSchema;
    protected Map<String, TableDesc> _extraTables;
    protected List<Parameter> _paramList;
    protected String _queryString;

    protected Statement _statement;
    protected List<TapSelectItem> _tapSelectItemList;
    protected List<SelectNavigator> _navigatorList = new ArrayList<SelectNavigator>();

    protected transient boolean navigated = false;
    
    public AdqlQuery() {
	}
	
	protected void init()
	{
        ExpressionNavigator en;
        ReferenceNavigator rn;
        FromItemNavigator fn;
        SelectNavigator sn;

//         en = new ExpressionNavigator();
//         rn = new ReferenceNavigator();
//         fn = new FromItemNavigator();
//         sn = new SelectNavigator(en, rn, fn);
//        _navigatorList.add(sn);

        en = new ExpressionValidator();
        rn = new ReferenceValidator();
        fn = new FromItemValidator();
        sn = new ValidatorNavigator(_tapSchema, en, rn, fn);
        _navigatorList.add(sn);

        sn = new AllColumnConverterNavigator(_tapSchema);
        _navigatorList.add(sn);

         en = new SelectListExtractor(_tapSchema, _extraTables);
         rn = null;
         fn = null;
         sn = new SelectListExtractorNavigator(en, rn, fn);
         _navigatorList.add(sn);
	}
	
	protected void receiveQuery()
	{
        try
        {
            _statement = ParserUtil.receiveQuery(_queryString);
        } catch (JSQLParserException e)
        {
            e.printStackTrace();
            throw new IllegalArgumentException(e);
        }
	}
	
    protected void doNavigate()
    {
        for (SelectNavigator sn : _navigatorList)
        {
            log.debug("Navigated by: " + sn.getClass().getName());
            
            ParserUtil.parseStatement(_statement, sn);
            
            if (sn instanceof SelectListExtractorNavigator)
            {
                SelectListExtractor slen = (SelectListExtractor) sn.getExpressionNavigator();
                _tapSelectItemList = slen.getTapSelectItemList();
            }
        }
        navigated = true; 
    }

	public void setTapSchema(TapSchema tapSchema) 
    {
        this._tapSchema = tapSchema;
    }

    public void setExtraTables(Map<String, TableDesc> extraTables)
    {
        this._extraTables = extraTables;
    }

    public void setParameterList( List<Parameter> paramList )
    {
        this._queryString = TapUtil.findParameterValue("QUERY", paramList);
        if (_queryString == null)
            throw new IllegalArgumentException( "parameter not found: QUERY" );
    }
    
	public String getSQL()
	{
		if (_queryString == null) throw new IllegalStateException();
		
		receiveQuery();
		init();
		doNavigate();
		return _statement.toString();
	}

	public List<TapSelectItem> getSelectList() 
    {
        if (_queryString == null || !navigated)
            throw new IllegalStateException();
        
        return _tapSelectItemList;
	}
}
