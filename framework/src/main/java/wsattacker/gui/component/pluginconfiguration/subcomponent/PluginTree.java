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
package wsattacker.gui.component.pluginconfiguration.subcomponent;

import it.cnr.imaa.essi.lablib.gui.checkboxtree.CheckboxTree;
import it.cnr.imaa.essi.lablib.gui.checkboxtree.TreeCheckingEvent;
import it.cnr.imaa.essi.lablib.gui.checkboxtree.TreeCheckingListener;
import it.cnr.imaa.essi.lablib.gui.checkboxtree.TreeCheckingModel;
import java.beans.PropertyChangeSupport;
import java.util.List;
import javax.swing.tree.TreeSelectionModel;
import org.apache.log4j.Logger;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.util.Category;

public class PluginTree
    extends CheckboxTree
{

    private static final Logger LOG = Logger.getLogger( PluginTree.class );

    private static final long serialVersionUID = 1L;

    public static final String PROP_CONTROLLER = "controller";

    private ControllerInterface controller;

    private final PluginTreeModel model;

    private final transient PropertyChangeSupport propertyChangeSupport = new java.beans.PropertyChangeSupport( this );

    public PluginTree( ControllerInterface controller )
    {
        super();
        // setController(controller);
        this.controller = controller;
        // setModel(new PluginTreeModel());
        this.model = new PluginTreeModel();
        setRootVisible( false );
        PluginTreeCellRenderer cellRenderer = new PluginTreeCellRenderer();
        cellRenderer.setPluginTree( this );
        setCellRenderer( cellRenderer );
        getCheckingModel().setCheckingMode( TreeCheckingModel.CheckingMode.PROPAGATE_PRESERVING_CHECK );
        getSelectionModel().setSelectionMode( TreeSelectionModel.SINGLE_TREE_SELECTION );
        addTreeCheckingListener( new TreeCheckingListener()
        {
            @Override
            public void valueChanged( TreeCheckingEvent e )
            {
                LOG.info( String.format( "PluginTree value changed: " + e.toString() ) );
                Object o = e.getPath().getLastPathComponent();
                if ( o instanceof AbstractPlugin )
                {
                    getController().setPluginActive( ( (AbstractPlugin) o ).getName(), e.isCheckedPath() );
                }
                else if ( o.getClass().isAssignableFrom( getModel().getRoot().getClass() ) )
                {
                    Object node = getModel().getRoot();
                    Object[] path = e.getPath().getPath();
                    for ( int i = 1; i < path.length; ++i )
                    {
                        node = getModel().getChild( node, getModel().getIndexOfChild( node, path[i] ) );
                    }
                    if ( node instanceof Category<?, ?> )
                    {
                        Category<String, AbstractPlugin> category;
                        category = (Category<String, AbstractPlugin>) node;
                        List<AbstractPlugin> list;
                        list = category.getLeafsRecursive();
                        for ( AbstractPlugin plugin : list )
                        {
                            getController().setPluginActive( plugin.getName(), e.isCheckedPath() );
                        }
                    }
                }
                repaint();
            }
        } );
    }

    public ControllerInterface getController()
    {
        return controller;
    }

    public void setController( ControllerInterface controller )
    {
        ControllerInterface oldController = this.controller;
        this.controller = controller;
        propertyChangeSupport.firePropertyChange( PROP_CONTROLLER, oldController, controller );
    }

    public PluginTreeModel getModel()
    {
        return model;
    }
}
