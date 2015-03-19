/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Mainka
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
package wsattacker.library.signatureWrapping.util.file;

import java.io.*;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;

public class FileUtilitites
{

    public static String readFileToString( String path )
        throws FileNotFoundException, IOException
    {
        FileInputStream stream = new FileInputStream( path );
        try
        {
            FileChannel fc = stream.getChannel();
            MappedByteBuffer bb = fc.map( FileChannel.MapMode.READ_ONLY, 0, fc.size() );
            /*
             * Instead of using default, pass in a decoder.
             */
            return Charset.defaultCharset().decode( bb ).toString();
        }
        finally
        {
            stream.close();
        }
    }

    public static void writeStringtoFile( String content, String path )
        throws IOException
    {
        FileWriter fw = new FileWriter( path );
        BufferedWriter bb = new BufferedWriter( fw );
        try
        {
            bb.write( content );
        }
        finally
        {
            bb.close();
        }
    }
}
