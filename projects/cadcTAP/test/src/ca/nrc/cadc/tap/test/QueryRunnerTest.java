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

package ca.nrc.cadc.tap.test;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

import ca.nrc.cadc.tap.QueryRunner;
import ca.nrc.cadc.uws.ErrorSummary;
import ca.nrc.cadc.uws.ExecutionPhase;
import ca.nrc.cadc.uws.Job;
import ca.nrc.cadc.uws.Parameter;
import ca.nrc.cadc.uws.Result;
import junit.framework.TestCase;

public class QueryRunnerTest extends TestCase
{
	private static final Level  DEFAULT_LEVEL = Level.DEBUG;
	private static final String LONG_FORMAT   = "%d{ABSOLUTE} [%t] %-5p %c{1} %x - %m\n";

	private static Logger logger;
 
	static {
    	ConsoleAppender appender = new ConsoleAppender( new PatternLayout(LONG_FORMAT) );
		BasicConfigurator.configure( appender );
		logger = Logger.getLogger(QueryRunnerTest.class);
		logger.info( "Logging initialized at level="+DEFAULT_LEVEL );
	}

	private QueryRunner runner = new QueryRunner();
	
	//  Most of the parameter validation testing
	//  is done in the Validator test classes.
	
	public void testValidParams() {

		List<Parameter> paramList = new ArrayList<Parameter>();
		paramList.add( new Parameter( "REQUEST", "doQuery" ) );
		paramList.add( new Parameter( "VERSION", "1.0" ) );
		paramList.add( new Parameter( "LANG",    "ADQL" ) );
		paramList.add( new Parameter( "QUERY",   "Sensible query" ) );
		
		Job job = new Job( "100",
				           ExecutionPhase.PENDING,
                           10L,
                           new Date(),
                           new Date(),
                           new Date(),
                           new Date(),
                           new ErrorSummary(),
                           "Owner",
                           "Run100",
                           new ArrayList<Result>(),
                           paramList );
		
		runner.setJob( job );
		runner.run();

		assertEquals( "ca.nrc.cadc.tap.parser.adql.exception.AdqlException: Invalid query syntax.",
			          job.getErrorSummary().getSummaryMessage() );

		assertEquals( "file:/tmp/QueryRunnerError100.xml",
				      job.getErrorSummary().getDocumentURI().toString() );

		assertEquals( "ERROR", job.getExecutionPhase().toString() ); // for now
		//assertEquals( "COMPLETED", job.getExecutionPhase().toString() );
	}
	
	public void testInvalidParams() {

		List<Parameter> paramList = new ArrayList<Parameter>();
		paramList.add( new Parameter( "REQUEST", "getCapabilities" ) );

		
		Job job = new Job( "200",
				           ExecutionPhase.PENDING,
                           10L,
                           new Date(),
                           new Date(),
                           new Date(),
                           new Date(),
                           new ErrorSummary(),
                           "Owner",
                           "Run200",
                           new ArrayList<Result>(),
                           paramList );
		
		runner.setJob( job );
		runner.run();
		
		assertEquals( "Unknown REQUEST value: getCapabilities",
				      job.getErrorSummary().getSummaryMessage() );
		
		assertEquals( "file:/tmp/QueryRunnerError200.xml",
				      job.getErrorSummary().getDocumentURI().toString() );
		
		assertEquals( "ERROR", job.getExecutionPhase().toString() );
	}
	
	public void testAdqlWithoutQueryParams() {

		List<Parameter> paramList = new ArrayList<Parameter>();
		paramList.add( new Parameter( "REQUEST", "doQuery" ) );
		paramList.add( new Parameter( "VERSION", "1.0" ) );
		paramList.add( new Parameter( "LANG",    "ADQL" ) );
		
		Job job = new Job( "300",
				           ExecutionPhase.PENDING,
                           10L,
                           new Date(),
                           new Date(),
                           new Date(),
                           new Date(),
                           new ErrorSummary(),
                           "Owner",
                           "Run300",
                           new ArrayList<Result>(),
                           paramList );
		
		runner.setJob( job );
		runner.run();

		assertEquals( "Parameter incorrect. No QUERY found.",
			          job.getErrorSummary().getSummaryMessage() );

		assertEquals( "file:/tmp/QueryRunnerError300.xml",
				      job.getErrorSummary().getDocumentURI().toString() );

		assertEquals( "ERROR", job.getExecutionPhase().toString() );
	}
	
}
