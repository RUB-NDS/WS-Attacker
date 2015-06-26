/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Altmeier
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
package wsattacker.plugin.intelligentdos.ui.helper;

import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import javax.swing.event.TableModelEvent;
import javax.swing.table.AbstractTableModel;

import wsattacker.library.intelligentdos.helper.CommonParamItem;

/**
 * @author Christian Altmeier
 */
public class CommonParamTableModel
    extends AbstractTableModel
{

    /**
	 * 
	 */
    private static final long serialVersionUID = 1L;

    private final Vector<CommonParamItem> commonParamItems = new Vector<CommonParamItem>();

    public CommonParamTableModel( int[][] ommonParamItemsArray )
    {
        for ( int[] possibleCommonParam : ommonParamItemsArray )
        {
            commonParamItems.add( new CommonParamItem( possibleCommonParam ) );
        }
    }

    public CommonParamTableModel( List<CommonParamItem> cpiList )
    {
        for ( CommonParamItem commonParamItem : cpiList )
        {
            commonParamItems.add( commonParamItem );
        }
    }

    @Override
    public int getRowCount()
    {
        return commonParamItems.size();
    }

    // Die Titel der einzelnen Columns
    @Override
    public String getColumnName( int column )
    {
        switch ( column )
        {
            case 0:
                return "requests";
            case 1:
                return "threads";
            case 2:
                return "millies between requests";
            default:
                return null;
        }
    }

    @Override
    public int getColumnCount()
    {
        return 3;
    }

    @Override
    public Integer getValueAt( int rowIndex, int columnIndex )
    {
        final CommonParamItem commonParamItem = commonParamItems.get( rowIndex );

        Integer valueAt = 0;
        switch ( columnIndex )
        {
            case 0:
                valueAt = commonParamItem.getNumberOfRequests();
                break;
            case 1:
                valueAt = commonParamItem.getNumberOfThreads();
                break;
            case 2:
                valueAt = commonParamItem.getMilliesBetweenRequests();
                break;
            default:
                throw new IllegalArgumentException( columnIndex + " is not defined!" );
        }

        return valueAt;
    }

    public void add( CommonParamItem commonParamItem )
    {
        commonParamItems.add( commonParamItem );

        TableModelEvent eAddRow = new TableModelEvent( this, TableModelEvent.ALL_COLUMNS, TableModelEvent.INSERT );

        fireTableChanged( eAddRow );
    }

    public void remove( int selectedRow )
    {
        if ( selectedRow < 0 || selectedRow >= commonParamItems.size() )
        {
            throw new IllegalArgumentException( "" );
        }

        commonParamItems.remove( selectedRow );

        TableModelEvent r_remove = new TableModelEvent( this, TableModelEvent.ALL_COLUMNS, TableModelEvent.DELETE );
        fireTableChanged( r_remove );
    }

    public CommonParamItem get( int selectedRow )
    {
        if ( selectedRow < 0 || selectedRow >= commonParamItems.size() )
        {
            throw new IllegalArgumentException( "" );
        }

        return commonParamItems.get( selectedRow );
    }

    public List<CommonParamItem> getItems()
    {
        return new ArrayList<CommonParamItem>( commonParamItems );
    }

}
