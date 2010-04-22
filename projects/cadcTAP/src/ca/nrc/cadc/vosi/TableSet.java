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

package ca.nrc.cadc.vosi;

import org.apache.log4j.Logger;
import org.jdom.Attribute;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.Namespace;

import ca.nrc.cadc.tap.schema.ColumnDesc;
import ca.nrc.cadc.tap.schema.SchemaDesc;
import ca.nrc.cadc.tap.schema.TableDesc;
import ca.nrc.cadc.tap.schema.TapSchema;

/**
 *
 * @author pdowler
 */
public class TableSet
{
    private static Logger log = Logger.getLogger(TableSet.class);

    private static String DEFAULT_SCHEMA = "default";
    
    private TapSchema _tapSchema;

    private Namespace xsi = Namespace.getNamespace("xsi", VOSI.XSI_NS_URI);
    private Namespace vosi = Namespace.getNamespace("vosi", VOSI.TABLES_NS_URI);
    private Namespace vod = Namespace.getNamespace("vod", VOSI.VODATASERVICE_NS_URI);

    public TableSet(TapSchema tapSchema)
    {
        this._tapSchema = tapSchema;
    }

    /**
     * @return the TapSchema as a document to be rendered as XML
     */
    public Document getDocument()
    {

        Element eleTableset = toXmlElement(_tapSchema);
        eleTableset.addNamespaceDeclaration(xsi);
        eleTableset.addNamespaceDeclaration(vod);

        Document document = new Document();
        document.addContent(eleTableset);
        return document;
    }

    /**
     * @param tapSchema
     * @return
     */
    private Element toXmlElement(TapSchema tapSchema)
    {
        Element eleTableset = new Element("tableset", vosi);
        //Comment comment = new Comment("This is a temporary solution as of 2010-03-12.");
        //eleTableset.addContent(comment);
        if (tapSchema.getSchemaDescs().size() == 0)
            throw new IllegalArgumentException("Error: at least one schema is required.");
        for (SchemaDesc sd : tapSchema.getSchemaDescs())
        {
            eleTableset.addContent(toXmlElement(sd));
        }
        return eleTableset;
    }

    /**
     * @param sd
     * @return
     */
    private Element toXmlElement(SchemaDesc sd)
    {
        Element eleSchema = new Element("schema");
        Element ele;
        ele = new Element("name");
        if (sd.getSchemaName() == null)
            ele.setText(DEFAULT_SCHEMA);
        else
            ele.setText(sd.getSchemaName());
        eleSchema.addContent(ele);
        if (sd.getTableDescs() != null)
            for (TableDesc td : sd.getTableDescs())
            {
                eleSchema.addContent(toXmlElement(td));
            }
        return eleSchema;
    }

    /**
     * @param td
     * @return
     */
    private Element toXmlElement(TableDesc td)
    {
        Element eleTable = new Element("table");
        eleTable.setAttribute("type", "output");

        Element ele;
        ele = new Element("name");
        ele.setText(td.getTableName());
        eleTable.addContent(ele);

        if (td.getColumnDescs() != null)
            for (ColumnDesc cd : td.getColumnDescs())
            {
                eleTable.addContent(toXmlElement(cd));
            }

        return eleTable;
    }

    /**
     * @param cd
     * @return
     */
    private Element toXmlElement(ColumnDesc cd)
    {
        Element eleColumn = new Element("column");

        addChild(eleColumn, "name", cd.getColumnName());
        addChild(eleColumn, "description", cd.getDescription());
        addChild(eleColumn, "unit", cd.getUnit());
        addChild(eleColumn, "ucd", cd.getUcd());
        addChild(eleColumn, "utype", cd.getUtype());

        Element eleDt = addChild(eleColumn, "dataType", cd.getDatatype());
        if (eleDt != null)
        {
            Attribute attType = new Attribute("type", vod.getPrefix() + ":TAP", xsi);
            eleDt.setAttribute(attType);

            if (cd.getSize() != null && cd.getSize() > 0)
                eleDt.setAttribute("size", cd.getSize().toString());
        }

        return eleColumn;
    }

    private Element addChild(Element eleParent, String chdName, String chdText)
    {
        Element ele = null;
        if (chdText != null && !chdText.equals(""))
        {
            ele = new Element(chdName);
            ele.setText(chdText);
            eleParent.addContent(ele);
        }
        return ele;
    }

    public TapSchema getTapSchema()
    {
        return _tapSchema;
    }

    public void setTapSchema(TapSchema tapSchema)
    {
        _tapSchema = tapSchema;
    }
}
