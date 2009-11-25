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

package ca.nrc.cadc.tap.writer;

import ca.nrc.cadc.tap.TableWriter;
import ca.nrc.cadc.tap.schema.ColumnDesc;
import ca.nrc.cadc.tap.schema.SchemaDesc;
import ca.nrc.cadc.tap.schema.TableDesc;
import ca.nrc.cadc.tap.writer.votable.TableDataElement;
import ca.nrc.cadc.tap.writer.votable.TableDataXMLOutputter;
import java.io.IOException;
import java.io.OutputStream;
import java.sql.ResultSet;
import java.util.List;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.Namespace;
import org.jdom.output.Format;
import org.jdom.output.XMLOutputter;
import ca.nrc.cadc.tap.parser.adql.TapSelectItem;
import ca.nrc.cadc.tap.schema.TapSchema;
import ca.nrc.cadc.tap.writer.votable.FieldElement;
import ca.nrc.cadc.tap.writer.formatter.Formatter;
import ca.nrc.cadc.tap.writer.formatter.FormatterFactory;

public class VOTableWriter implements TableWriter
{
    public static final String VOTABLE_VERSION  = "1.2";
    public static final String XSI_NS_URI = "http://www.w3.org/2001/XMLSchema-instance";
    public static final String VOTABLE_NS_URI = "http://www.ivoa.net/xml/VOTable/v1.2";
    public static final String STC_NS = "xmlns:stc";
    public static final String STC_NS_URI = "http://www.ivoa.net/xml/STC/v1.30";

    protected TapSchema tapSchema;

    protected List<TapSelectItem> selectList;

    public VOTableWriter() { }

    public String getExtension()
    {
        return "xml";
    }

    public void setSelectList(List<TapSelectItem> items)
    {
        this.selectList = items;
    }

    public void setTapSchema(TapSchema schema)
    {
        this.tapSchema = schema;
    }
    
    public void write(ResultSet resultSet, OutputStream output)
        throws IOException
    {
        if (selectList == null)
            throw new IllegalStateException("SelectList cannot be null, set using setSelectList()");
        if (tapSchema == null)
            throw new IllegalStateException("TapSchema cannot be null, set using setTapSchema()");

        List<Formatter> formatters = FormatterFactory.getFormatters(tapSchema, selectList);

        Document document = createDocument();
        Element votable = document.getRootElement();

        // Create the RESOURCE element and add to the VOTABLE element.
        Element resource = new Element("RESOURCE");
        votable.addContent(resource);

        // Create the TABLE element and add to the RESOURCE element.
        Element table = new Element("TABLE");
        resource.addContent(table);

        // Add the metadata elements.
        for (TapSelectItem selectItem : selectList)
            table.addContent(getMetaDataElement(selectItem));

        // Create the DATA element and add to the TABLE element.
        Element data = new Element("DATA");
        table.addContent(data);

        // Create the TABLEDATA element and add the to DATA element.
        Element tableData = new TableDataElement(tapSchema, resultSet, formatters);
        data.addContent(tableData);

        // Write out the VOTABLE.
        XMLOutputter outputter = new TableDataXMLOutputter(tapSchema);
        outputter.setFormat(Format.getPrettyFormat());
        outputter.output(document, output);
    }
	
    public void write( Throwable thrown, OutputStream output )
        throws IOException
    {
        Document document = createDocument();
        Element votable = document.getRootElement();
        
        // Create the RESOURCE element and add to the VOTABLE element.
        Element resource = new Element("RESOURCE");
        votable.addContent(resource);

        // Create the INFO element and add to the RESOURCE element.
        Element info = new Element("INFO");
        info.setAttribute("name", "QUERY_STATUS");
        info.setAttribute("value", "ERROR");
        resource.addContent(info);

        // Create the DESCRIPTION element and add to the INFO element.
        Element description = new Element("DESCRIPTION");
        description.setText(getThrownExceptions(thrown));
        info.addContent(description);

        // Write out the VOTABLE.
        XMLOutputter outputter = new XMLOutputter();
        outputter.setFormat(Format.getPrettyFormat());
        outputter.output(document, output);
    }
    
    private Document createDocument()
    {
        // the root VOTABLE element
        Namespace vot = Namespace.getNamespace("vot", VOTABLE_NS_URI);
        Namespace xsi = Namespace.getNamespace("xsi", XSI_NS_URI);
        Element votable = new Element("VOTABLE", vot);
        votable.setAttribute("version", VOTABLE_VERSION);
        votable.addNamespaceDeclaration(xsi);
        
        Document document = new Document();
        document.addContent(votable);
        
        return document;
    }

    // Build a FIELD Element for the column specified by the TapSelectItem.
    private Element getMetaDataElement(TapSelectItem selectItem)
    {
        for (SchemaDesc schemaDesc : tapSchema.schemaDescs)
        {
            for (TableDesc tableDesc : schemaDesc.tableDescs)
            {
                if (tableDesc.tableName.equals(selectItem.getTableName()))
                {
                    for (ColumnDesc columnDesc: tableDesc.columnDescs)
                    {
                        if (columnDesc.columnName.equals(selectItem.getColumnName()))
                        {
                            return new FieldElement(selectItem, columnDesc);
                        }
                    }
                }
            }
        }
        // select item did not match a column, must be a function call or expression
        Element e = new Element("FIELD");
        e.setAttribute("name", selectItem.getAlias());
        return e;
    }

    // Build a String containing the nested Exception messages.
    private String getThrownExceptions(Throwable thrown)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(thrown.getClass().getSimpleName());
        sb.append(": ");
        sb.append(thrown.getMessage() == null ? "" : thrown.getMessage());
        while (thrown.getCause() != null)
        {
            thrown = thrown.getCause();
            sb.append(" ");
            sb.append(thrown.getClass().getSimpleName());
            sb.append(": ");
            sb.append(thrown.getMessage() == null ? "" : thrown.getMessage());
        }
        return sb.toString();
    }

}
