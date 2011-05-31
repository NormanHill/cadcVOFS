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

import ca.nrc.cadc.tap.writer.VOTableWriter;
import ca.nrc.cadc.uws.SyncOutput;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import org.apache.log4j.Logger;

import ca.nrc.cadc.tap.parser.TapSelectItem;
import ca.nrc.cadc.tap.schema.SchemaDesc;
import ca.nrc.cadc.tap.schema.TableDesc;
import ca.nrc.cadc.tap.schema.TapSchema;
import ca.nrc.cadc.tap.schema.TapSchemaDAO;
import ca.nrc.cadc.uws.ErrorSummary;
import ca.nrc.cadc.uws.ErrorType;
import ca.nrc.cadc.uws.ExecutionPhase;
import ca.nrc.cadc.uws.Job;
import ca.nrc.cadc.uws.JobManager;
import ca.nrc.cadc.uws.Parameter;
import ca.nrc.cadc.uws.Result;
import ca.nrc.cadc.uws.SyncJobRunner;
import java.util.ArrayList;
import javax.naming.NameNotFoundException;

/**
 * Implementation of the JobRunner interface from the cadcUWS framework. This is the
 * main class that implements TAP semantics; it is usable with both the async and sync
 * servlet configurations from cadcUWS.
 * </p><p>
 * This class dynamically loads and uses implementation classes as described in the
 * package documentation. This allows one to control the behavior of several key components:
 * query processing, upload support, and writing the result-set to the output file format.
 * </p><p>
 * In addition, this class uses JDNI to find <code>java.sql.DataSource</code> instances for 
 * executing database statements. 
 * </p>
 * <ul>
 * <li>A datasource named <b>jdbc/tapuser</b> is required; this datasource
 * is used to query the TAP_SCHEMA and to run user-queries. The connection(s) provided by this
 * datasource must have read permission to the TAP_SCHEMA and all tables described within the
 * TAP_SCHEMA.</li>
 * <li>A datasource named <b>jdbc/tapuploadadm</b> is optional; this datasource is used to create tables
 * in the TAP_UPLOAD schema and to populate these tables with content from uploaded tables. If this 
 * datasource is provided, it is passed to the UploadManager implementation. For uploads to actually work, 
 * the connection(s) provided by the datasource must have create table permission in the current database and
 * TAP_UPLOAD schema.</li>
 * </ul>
 * 
 * @author pdowler
 */
public class QueryRunner implements SyncJobRunner
{
    private static final Logger logger = Logger.getLogger(QueryRunner.class);

    private static final HashMap<String, String> langQueries = new HashMap<String, String>();

    private static String queryDataSourceName = "jdbc/tapuser";
    private static String uploadDataSourceName = "jdbc/tapuploadadm";

    // names of plugin classes that must be provided by service implementation
    private static String fileStoreClassName = "ca.nrc.cadc.tap.impl.FileStoreImpl";
    private static String resultStoreImplClassName = "ca.nrc.cadc.tap.impl.ResultStoreImpl";
    private static String uploadManagerClassName = "ca.nrc.cadc.tap.impl.UploadManagerImpl";
    private static String sqlParserClassName = "ca.nrc.cadc.tap.impl.SqlQueryImpl";
    private static String adqlParserClassName = "ca.nrc.cadc.tap.impl.AdqlQueryImpl";
    private static String pqlParserClassName = "ca.nrc.cadc.tap.impl.PqlQueryImpl";

    // optional plugin classes that may be provided to override default behaviour
    private static String maxrecValidatorClassName = "ca.nrc.cadc.tap.impl.MaxRecValidatorImpl";

    static
    {
        langQueries.put("ADQL", adqlParserClassName);
        langQueries.put("SQL", sqlParserClassName);
        langQueries.put("PQL", pqlParserClassName);
    }

    private String jobID;
    private Job job;
    private JobManager manager;
    private SyncOutput syncOutput;

    public QueryRunner()
    {
        syncOutput = null;
    }

    public void setJob(Job job)
    {
        this.job = job;
        jobID = job.getID();
    }

    public Job getJob()
    {
        return job;
    }

    public void setJobManager(JobManager jm)
    {
        this.manager = jm;
    }

    public URL getRedirectURL()
    {
        return null;
    }

    public void setOutput(SyncOutput syncOutput)
    {
        this.syncOutput = syncOutput;
    }

    public void run()
    {
        logger.debug("START");
        List<Long> tList = new ArrayList<Long>();
        List<String> sList = new ArrayList<String>();

        tList.add(System.currentTimeMillis());
        sList.add("start");

        // check job state, TODO optimise this
        this.job = manager.getJob(jobID);
        if (job == null || job.getExecutionPhase().equals(ExecutionPhase.ABORTED))
        {
            logger.debug("job aborted");
            return;
        }
        tList.add(System.currentTimeMillis());
        sList.add("check if aborted: ");

        
        
        FileStore fs = null;
        ResultStore rs = null;
        if (syncOutput == null)
        {
            // try to instantiate a deprecated FileStore instance
            try
            {
                logger.debug("loading " + fileStoreClassName);
                fs = (FileStore) Class.forName(fileStoreClassName).newInstance();
            }
            catch (Throwable t)
            {
                logger.warn("Failed to instantiate FileStore class: " + fileStoreClassName);
            }

            // try to instantiate a ResultStore instance
            try
            {
                logger.debug("loading " + resultStoreImplClassName);
                rs = (ResultStore) Class.forName(resultStoreImplClassName).newInstance();
            }
            catch (Throwable t)
            {
                logger.warn("Failed to instantiate ResultStore class: " + resultStoreImplClassName);
            }
        }

        // Check if a store or stream have been set for a context
        if (fs == null && rs == null && syncOutput == null)
        {
            throw new RuntimeException("async mode: Failed to instantiate a FileStore or ResultStore class");
        }

        try
        {
            logger.debug("setting/persisting ExecutionPhase = " + ExecutionPhase.EXECUTING);
            job.setExecutionPhase(ExecutionPhase.EXECUTING);
            this.job = manager.persist(job);

            tList.add(System.currentTimeMillis());
            sList.add("set phase = EXECUTING: ");

            // start processing the job
            List<Parameter> paramList = job.getParameterList();

            logger.debug("invoking TapValiator for REQUEST and VERSION...");
            TapValidator tapValidator = new TapValidator();
            tapValidator.validate(paramList);

            tList.add(System.currentTimeMillis());
            sList.add("initialisation: ");

            logger.debug("find DataSource via JNDI lookup...");
            Context initContext = new InitialContext();
            Context envContext = (Context) initContext.lookup("java:/comp/env");
            DataSource queryDataSource = (DataSource) envContext.lookup(queryDataSourceName);
            // this one is optional, so take care
            DataSource uploadDataSource = null;
            try
            {
                uploadDataSource = (DataSource) envContext.lookup(uploadDataSourceName);
            }
            catch (NameNotFoundException nex)
            {
                logger.warn(nex.toString());
            }

            if (queryDataSource == null) // application server config issue
                throw new RuntimeException("failed to find the query DataSource");

            tList.add(System.currentTimeMillis());
            sList.add("find DataSources via JNDI: ");

            // check job state, TODO optimise this
            this.job = manager.getJob(jobID);
            if (job == null || job.getExecutionPhase().equals(ExecutionPhase.ABORTED))
            {
                logger.debug("job aborted");
                return;
            }
            tList.add(System.currentTimeMillis());
            sList.add("check if aborted: ");

            logger.debug("reading TapSchema...");
            TapSchemaDAO dao = new TapSchemaDAO(queryDataSource);
            TapSchema tapSchema = dao.get();

            tList.add(System.currentTimeMillis());
            sList.add("read tap_schema: ");

            logger.debug("loading " + uploadManagerClassName);
            Class umc = Class.forName(uploadManagerClassName);
            UploadManager uploadManager = (UploadManager) umc.newInstance();
            uploadManager.setDataSource(uploadDataSource);
            logger.debug("invoking UploadManager for UPLOAD...");
            Map<String, TableDesc> tableDescs = uploadManager.upload(paramList, job.getID());

            if (tableDescs != null)
            {
                logger.debug("adding TAP_UPLOAD SchemaDesc to TapSchema...");
                SchemaDesc tapUploadSchema = new SchemaDesc();
                tapUploadSchema.setSchemaName("TAP_UPLOAD");
                tapUploadSchema.setTableDescs(new ArrayList(tableDescs.values()));
                tapSchema.schemaDescs.add(tapUploadSchema);
            }

            logger.debug("invoking MaxRecValidator...");
            MaxRecValidator maxRecValidator = new MaxRecValidator();
            try
            {
                Class c = Class.forName(maxrecValidatorClassName);
                maxRecValidator = (MaxRecValidator) c.newInstance();
            }
            catch (Throwable ignore)
            {
            }
            logger.debug("using " + maxRecValidator.getClass().getName());
            maxRecValidator.setJob(job);
            maxRecValidator.setSynchronousMode(syncOutput != null);
            maxRecValidator.setTapSchema(tapSchema);
            maxRecValidator.setExtraTables(tableDescs);
            Integer maxRows = maxRecValidator.validate(paramList);

            logger.debug("invoking TapValidator to get LANG...");
            String lang = tapValidator.getLang();
            String cname = langQueries.get(lang);
            if (cname == null)
                throw new UnsupportedOperationException("unknown LANG: " + lang);

            logger.debug("loading TapQuery " + cname);
            Class tqc = Class.forName(cname);
            TapQuery tapQuery = (TapQuery) tqc.newInstance();
            tapQuery.setTapSchema(tapSchema);
            tapQuery.setExtraTables(tableDescs);
            tapQuery.setParameterList(paramList);
            if (maxRows != null)
                tapQuery.setMaxRowCount(maxRows + 1); // +1 so the TableWriter can detect overflow

            logger.debug("invoking TapQuery...");
            String sql = tapQuery.getSQL();
            List<TapSelectItem> selectList = tapQuery.getSelectList();

            logger.debug("invoking TableWriterFactory for FORMAT...");
            TableWriter tableWriter = TableWriterFactory.getWriter(job.getParameterList());
            tableWriter.setTapSchema(tapSchema);
            tableWriter.setSelectList(selectList);
            tableWriter.setJobID(jobID);
            tableWriter.setParameterList(paramList);
            if (maxRows != null)
                tableWriter.setMaxRowCount(maxRows);

            tList.add(System.currentTimeMillis());
            sList.add("parse/convert query: ");

            Connection connection = null;
            PreparedStatement pstmt = null;
            ResultSet resultSet = null;
            File tmpFile = null;
            URL url = null;
            try
            {
                if (maxRows == null || maxRows.intValue() > 0)
                {
                    logger.debug("getting database connection...");
                    connection = queryDataSource.getConnection();

                    // manually control transaction, make fetch size (client batch size) small,
                    // and restrict to forward only so that client memory usage is minimal since
                    // we are only interested in reading the ResultSet once
                    connection.setAutoCommit(false);
                    pstmt = connection.prepareStatement(sql);
                    pstmt.setFetchSize(1000);
                    pstmt.setFetchDirection(ResultSet.FETCH_FORWARD);
                    
                    logger.info("executing query: " + sql);
                    resultSet = pstmt.executeQuery();
                }

                tList.add(System.currentTimeMillis());
                sList.add("execute query and get ResultSet: ");

                // TODO if checking for abort was fast, check it here and save writing and storing
                if (syncOutput != null)
                {
                    String contentType = tableWriter.getContentType();
                    logger.debug("streaming output: " + contentType);
                    syncOutput.setHeader("Content-Type", contentType);
                    tableWriter.write(resultSet, syncOutput.getOutputStream());
                    tList.add(System.currentTimeMillis());
                    sList.add("stream Result set as " + contentType + ": ");
                }
                else
                {
                    String filename = "result_" + job.getID() + "." + tableWriter.getExtension();
                    logger.debug("result filename: " + filename);
                    if (rs != null)
                    {
                        logger.debug("setting ResultStore filename: " + filename);
                        rs.setJob(job);
                        rs.setFilename(filename);
                        rs.setContentType(tableWriter.getContentType());
                        url = rs.put(resultSet, tableWriter);
                        tList.add(System.currentTimeMillis());
                        sList.add("write ResultSet to ResultStore: ");
                    }
                    else
                    {
                        tmpFile = new File(fs.getStorageDir(), filename);
                        logger.debug("writing ResultSet to " + tmpFile);
                        OutputStream ostream = new FileOutputStream(tmpFile);
                        tableWriter.write(resultSet, ostream);
                        ostream.close();
                        tList.add(System.currentTimeMillis());
                        sList.add("write ResultSet to tmp file: ");

                        logger.debug("storing results with FileStore...");
                        fs.setJobID(jobID);
                        fs.setParameterList(paramList);
                        url = fs.put(tmpFile);
                        tList.add(System.currentTimeMillis());
                        sList.add("store tmp file with FileStore: ");
                    }
                }
                logger.debug("executing query... [OK]");
            }
            catch (SQLException ex)
            {
                logger.error("SQL Execution error.", ex);
                throw ex;
            }
            finally
            {
                if (connection != null)
                {
                    try
                    {
                        connection.setAutoCommit(true);
                    }
                    catch(Throwable ignore) { }
                    try
                    {
                        resultSet.close();
                    }
                    catch (Throwable ignore) { }
                    try
                    {
                        pstmt.close();
                    }
                    catch (Throwable ignore) { }
                    try
                    {
                        connection.close();
                    }
                    catch (Throwable ignore) { }
                }
            }

            // check job state, TODO optimise this
            this.job = manager.getJob(jobID);
            if (job == null || job.getExecutionPhase().equals(ExecutionPhase.ABORTED))
            {
                logger.debug("job aborted");
                return;
            }

            if (syncOutput == null)
            {
                Result res = new Result("result", url);
                List<Result> results = new ArrayList<Result>();
                results.add(res);
                job.setResultsList(results);
            }

            logger.debug("setting ExecutionPhase = " + ExecutionPhase.COMPLETED);
            job.setExecutionPhase(ExecutionPhase.COMPLETED);
            this.job = manager.persist(job);
        }
        catch (Throwable t)
        {
            String errorMessage = null;
            URL errorURL = null;
            try
            {
                tList.add(System.currentTimeMillis());
                sList.add("encounter failure: ");

                errorMessage = t.getClass().getSimpleName() + ":" + t.getMessage();
                logger.debug("BADNESS", t);
                logger.debug("Error message: " + errorMessage);
                VOTableWriter ewriter = new VOTableWriter();
                ewriter.setParameterList(job.getParameterList()); // to check custom xml format
                if (syncOutput != null)
                {
                    syncOutput.setHeader("Content-Type", ewriter.getContentType());
                    ewriter.write(t, syncOutput.getOutputStream());
                }
                else
                {
                    String filename = "error_" + job.getID() + "." + ewriter.getExtension();
                    if (rs != null)
                    {
                        rs.setJob(job);
                        rs.setFilename(filename);
                        rs.setContentType(ewriter.getContentType());
                        errorURL = rs.put(t, ewriter);

                        tList.add(System.currentTimeMillis());
                        sList.add("store error with ResultStore ");
                    }
                    else
                    {
                        File errorFile = new File(fs.getStorageDir(), filename);
                        logger.debug("Error file: " + errorFile.getAbsolutePath());
                        FileOutputStream errorOutput = new FileOutputStream(errorFile);
                        ewriter.write(t, errorOutput);
                        errorOutput.close();

                        tList.add(System.currentTimeMillis());
                        sList.add("write error to tmp file: ");
                        fs.setJobID(jobID);
                        errorURL = fs.put(errorFile);

                        tList.add(System.currentTimeMillis());
                        sList.add("store error file with FileStore ");
                    }
                }
                
                logger.debug("Error URL: " + errorURL);
                // check job state, TODO optimise this
                this.job = manager.getJob(jobID);
                if (job == null || job.getExecutionPhase().equals(ExecutionPhase.ABORTED))
                {
                    logger.debug("job aborted");
                    return;
                }
                logger.debug("setting ExecutionPhase = " + ExecutionPhase.ERROR);
                job.setExecutionPhase(ExecutionPhase.ERROR);
                ErrorSummary es = new ErrorSummary(errorMessage, ErrorType.FATAL, true);
                es.setDocumentURL(errorURL);
                job.setErrorSummary(es);
                this.job = manager.persist(job);
            }
            catch (Throwable t2)
            {
                logger.error("failed to persist error", t2);
                // this is really bad
                logger.debug("setting ExecutionPhase = " + ExecutionPhase.ERROR);
                job.setExecutionPhase(ExecutionPhase.ERROR);
                ErrorSummary es = new ErrorSummary(errorMessage, ErrorType.FATAL, false);
                job.setErrorSummary(es);
                this.job = manager.persist(job);
            }
        }
        finally
        {
            tList.add(System.currentTimeMillis());
            sList.add("set final job state: ");

            for (int i = 1; i < tList.size(); i++)
            {
                long dt = tList.get(i) - tList.get(i - 1);
                logger.info(job.getID() + " -- " + sList.get(i) + dt + "ms");
            }

            logger.debug("DONE");
        }
    }
    
}
