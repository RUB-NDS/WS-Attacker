/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2010 Christian Mainka
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
package wsattacker.gui.component.pluginconfiguration.option;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JList;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import wsattacker.main.composition.plugin.option.AbstractOptionMultiFiles;

/**
 * @author christian
 */
public class OptionMultiFileGUI_NBTest
{

    final private static int FILES_TO_CREATE = 3;

    final private static String FILENAME = "FILE_";

    public OptionMultiFileGUI_NBTest()
    {
    }

    @Test
    public void testOptionMultiFile()
    {
        List<File> fileList = new ArrayList<File>();
        for ( int i = 0; i < FILES_TO_CREATE; ++i )
        {
            File fileMock = createMock( File.class );
            String path = String.format( "%s%d", FILENAME, i );
            expect( fileMock.getName() ).andReturn( path );
            fileList.add( fileMock );
        }
        replay( fileList.toArray() );
        OptionMultiFileGUI_NB multiFile = new OptionMultiFileGUI_NB();
        JList jList = multiFile.getFileList();
        JButton jButton = multiFile.getRemoveButton();

        AbstractOptionMultiFiles option = multiFile.getOption();
        option.setFiles( fileList );
        assertThat( fileList, hasSize( FILES_TO_CREATE ) );
        assertThat( jList.getModel().getSize(), is( FILES_TO_CREATE ) );
        jList.setSelectedIndex( FILES_TO_CREATE - 1 );
        jButton.doClick();
        assertThat( jList.getModel().getSize(), is( FILES_TO_CREATE - 1 ) );

        multiFile.bindingDoUnbind();
        verify( fileList.toArray() );
    }
}
