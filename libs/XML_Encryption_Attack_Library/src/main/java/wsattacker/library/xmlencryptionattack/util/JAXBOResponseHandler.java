/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Dennis Kupser
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

package wsattacker.library.xmlencryptionattack.util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.mode.OracleResponseCollector;

/**
 * @author Dennis
 */
public class JAXBOResponseHandler
{
    // Export
    public static void marshal( List<OracleResponse> oracleResponses, File selectedFile )
        throws IOException, JAXBException
    {
        JAXBContext context;
        context = JAXBContext.newInstance( OracleResponseCollector.class );
        Marshaller m = context.createMarshaller();
        m.setProperty( Marshaller.JAXB_FORMATTED_OUTPUT, true );
        m.marshal( new OracleResponseCollector( oracleResponses ), selectedFile );
    }

    // Import
    public static List<OracleResponse> unmarshal( File importFile )
        throws JAXBException
    {
        OracleResponseCollector respCollector = null;
        JAXBContext context = JAXBContext.newInstance( OracleResponseCollector.class );
        Unmarshaller um = context.createUnmarshaller();
        respCollector = (OracleResponseCollector) um.unmarshal( importFile );

        return respCollector.getData();
    }

}
