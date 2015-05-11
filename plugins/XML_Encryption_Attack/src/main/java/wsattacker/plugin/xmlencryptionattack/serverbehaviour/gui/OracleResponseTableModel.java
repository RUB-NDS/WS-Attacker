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

package wsattacker.plugin.xmlencryptionattack.serverbehaviour.gui;

import java.util.List;
import javax.swing.table.AbstractTableModel;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse.Result;

/**
 * @author Dennis
 */
public class OracleResponseTableModel
    extends AbstractTableModel
{
    // names of columns
    private static final String[] COLUMN_NAMES = { "Row", "Oracle Result" };

    private static final Class<?>[] COLUMN_CLASSES = { int.class, Result.class };

    // index columns
    protected static final int COLUMN_IDX_ROW = 0;

    protected static final int COLUMN_IDX_ORACLERESULT = 1;

    private final List<OracleResponse> m_Responses;

    public OracleResponseTableModel( final List<OracleResponse> responses )
    {
        this.m_Responses = responses;
    }

    @Override
    public int getRowCount()
    {
        return m_Responses.size();
    }

    @Override
    public int getColumnCount()
    {
        return COLUMN_NAMES.length;
    }

    @Override
    public Object getValueAt( int rowIndex, int columnIndex )
    {
        final OracleResponse response = this.m_Responses.get( rowIndex );

        if ( COLUMN_IDX_ROW == columnIndex )
        {
            return ( rowIndex + 1 );
        }

        if ( COLUMN_IDX_ORACLERESULT == columnIndex )
        {
            return (Result) response.getResult();
        }

        throw new IllegalArgumentException( "Invalid column index: " + columnIndex );

    }

    @Override
    public void setValueAt( final Object value, final int rowIndex, final int columnIndex )
    {
        final OracleResponse response = this.m_Responses.get( rowIndex );

        if ( COLUMN_IDX_ORACLERESULT == columnIndex )
        {
            response.setResult( (Result) value );
        }

        fireTableCellUpdated( rowIndex, columnIndex );

    }

    @Override
    public String getColumnName( int columnIndex )
    {
        return COLUMN_NAMES[columnIndex];
    }

    @Override
    public boolean isCellEditable( final int rowIndex, final int columnIndex )
    {
        return COLUMN_IDX_ORACLERESULT == columnIndex;
    }

    public void addResponse( OracleResponse oracResp )
    {
        m_Responses.add( oracResp );
        fireTableDataChanged();
    }

    public void update()
    {
        fireTableRowsInserted( COLUMN_IDX_ROW, m_Responses.size() );
    }

}
