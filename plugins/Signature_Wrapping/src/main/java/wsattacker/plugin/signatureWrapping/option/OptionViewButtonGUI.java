/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2011 Christian Mainka
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
package wsattacker.plugin.signatureWrapping.option;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.text.NumberFormat;

import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JEditorPane;
import javax.swing.JFormattedTextField;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JSlider;
import javax.swing.JTextArea;
import javax.swing.LayoutStyle;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import wsattacker.gui.component.pluginconfiguration.composition.OptionGUI;
import wsattacker.gui.util.XmlTextPane;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.signatureWrapping.util.signature.SignatureManager;
import wsattacker.library.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.library.signatureWrapping.xpath.wrapping.WrappingOracle;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.plugin.signatureWrapping.SignatureWrapping;

/**
 * This code was edited or generated using CloudGarden's Jigloo SWT/Swing GUI Builder, which is free for non-commercial
 * use. If Jigloo is being used commercially (ie, by a corporation, company or business for any purpose whatever) then
 * you should purchase a license for each developer using Jigloo. Please visit www.cloudgarden.com for details. Use of
 * Jigloo implies acceptance of these licensing terms. A COMMERCIAL LICENSE HAS NOT BEEN PURCHASED FOR THIS MACHINE, SO
 * JIGLOO OR THIS CODE CANNOT BE USED LEGALLY FOR ANY CORPORATE OR COMMERCIAL PURPOSE.
 */
public class OptionViewButtonGUI
    extends OptionGUI
{

    private SignatureWrapping signateWrappingPlugin;

    private static final long serialVersionUID = 1L;

    private JEditorPane name;

    private JEditorPane description;

    private JLabel maxPossibilitiesLabel;

    private JButton closeButton;

    private JScrollPane jScrollPane1;

    private XmlTextPane xml;

    private JTextArea logLabel;

    private JLabel headline;

    private JLabel ofLabel;

    private JFormattedTextField directChooser;

    private JSlider possibilitySwitcher;

    private JDialog viewDialog;

    private JButton viewButton;

    private JScrollPane descriptionScrollPane;

    private JScrollPane nameScrollPane;

    private WrappingOracle wrappingOracle;

    private AbstractOption option;

    public OptionViewButtonGUI( AbstractPlugin plugin, OptionViewButton option )
    {
        this.option = option;
        signateWrappingPlugin = (SignatureWrapping) plugin;
        GroupLayout thisLayout = new GroupLayout( this );
        this.setLayout( thisLayout );
        {
            viewButton = new JButton();
            viewButton.setText( "View" );
            viewButton.addActionListener( new ActionListener()
            {
                @Override
                public void actionPerformed( ActionEvent evt )
                {
                    getViewDialog().setVisible( true );
                }
            } );
        }
        {
            descriptionScrollPane = new JScrollPane();
            descriptionScrollPane.setVerticalScrollBarPolicy( ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER );
            descriptionScrollPane.setHorizontalScrollBarPolicy( ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER );
            descriptionScrollPane.setBorder( BorderFactory.createEmptyBorder( 0, 0, 0, 0 ) );
        }
        {
            nameScrollPane = new JScrollPane();
            nameScrollPane.setHorizontalScrollBarPolicy( ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER );
            nameScrollPane.setVerticalScrollBarPolicy( ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER );
            nameScrollPane.setBorder( BorderFactory.createEmptyBorder( 0, 0, 0, 0 ) );
            {
                name = new JEditorPane();
                nameScrollPane.setViewportView( name );
                name.setPreferredSize( new java.awt.Dimension( 85, 16 ) );
                name.setBackground( getBackground() );
                name.setText( plugin.getName() );
            }
        }
        {
            description = new JEditorPane();
            description.setFont( new java.awt.Font( "Dialog", 2, 12 ) );
            description.setBackground( getBackground() );
            description.setText( option.getDescription() );
            description.setEditable( false );
        }
        thisLayout.setHorizontalGroup( thisLayout.createSequentialGroup().addContainerGap().addComponent( nameScrollPane,
                                                                                                          GroupLayout.PREFERRED_SIZE,
                                                                                                          85,
                                                                                                          GroupLayout.PREFERRED_SIZE ).addPreferredGap( LayoutStyle.ComponentPlacement.UNRELATED ).addGroup( thisLayout.createParallelGroup().addGroup( GroupLayout.Alignment.LEADING,
                                                                                                                                                                                                                                                        thisLayout.createSequentialGroup().addGap( 174,
                                                                                                                                                                                                                                                                                                   174,
                                                                                                                                                                                                                                                                                                   174 ).addComponent( viewButton,
                                                                                                                                                                                                                                                                                                                       GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                       70,
                                                                                                                                                                                                                                                                                                                       GroupLayout.PREFERRED_SIZE ).addGap( 10 ) ).addComponent( descriptionScrollPane,
                                                                                                                                                                                                                                                                                                                                                                                 GroupLayout.Alignment.LEADING,
                                                                                                                                                                                                                                                                                                                                                                                 0,
                                                                                                                                                                                                                                                                                                                                                                                 254,
                                                                                                                                                                                                                                                                                                                                                                                 Short.MAX_VALUE ).addGroup( GroupLayout.Alignment.LEADING,
                                                                                                                                                                                                                                                                                                                                                                                                             thisLayout.createSequentialGroup().addComponent( description,
                                                                                                                                                                                                                                                                                                                                                                                                                                                              0,
                                                                                                                                                                                                                                                                                                                                                                                                                                                              242,
                                                                                                                                                                                                                                                                                                                                                                                                                                                              Short.MAX_VALUE ).addGap( 0,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        12,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        GroupLayout.PREFERRED_SIZE ) ) ) );
        thisLayout.setVerticalGroup( thisLayout.createParallelGroup().addGroup( GroupLayout.Alignment.LEADING,
                                                                                thisLayout.createSequentialGroup().addComponent( viewButton,
                                                                                                                                 GroupLayout.PREFERRED_SIZE,
                                                                                                                                 19,
                                                                                                                                 GroupLayout.PREFERRED_SIZE ).addPreferredGap( LayoutStyle.ComponentPlacement.RELATED,
                                                                                                                                                                               14,
                                                                                                                                                                               GroupLayout.PREFERRED_SIZE ).addComponent( description,
                                                                                                                                                                                                                          GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                          25,
                                                                                                                                                                                                                          GroupLayout.PREFERRED_SIZE ).addPreferredGap( LayoutStyle.ComponentPlacement.RELATED ).addComponent( descriptionScrollPane,
                                                                                                                                                                                                                                                                                                                               GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                               21,
                                                                                                                                                                                                                                                                                                                               GroupLayout.PREFERRED_SIZE ) ).addComponent( nameScrollPane,
                                                                                                                                                                                                                                                                                                                                                                            GroupLayout.Alignment.LEADING,
                                                                                                                                                                                                                                                                                                                                                                            0,
                                                                                                                                                                                                                                                                                                                                                                            85,
                                                                                                                                                                                                                                                                                                                                                                            Short.MAX_VALUE ) );
        this.setPreferredSize( new java.awt.Dimension( 369, 66 ) );
    }

    public JDialog getViewDialog()
    {
        createWrappingOracle();
        if ( viewDialog == null )
        {
            viewDialog = new JDialog();
            GroupLayout viewDialogLayout = new GroupLayout( viewDialog.getContentPane() );
            viewDialog.getContentPane().setLayout( viewDialogLayout );
            viewDialog.setPreferredSize( new java.awt.Dimension( 740, 591 ) );
            {
                headline = new JLabel();
                headline.setText( "View Wrapping Possibilites" );
                headline.setHorizontalAlignment( SwingConstants.CENTER );
                headline.setFont( new java.awt.Font( "Arial", 1, 14 ) );
            }
            {
                possibilitySwitcher = new JSlider();
                possibilitySwitcher.setMinimum( 1 );
                possibilitySwitcher.setPaintTicks( true );
                possibilitySwitcher.setPaintLabels( false );
                possibilitySwitcher.setSnapToTicks( false );
                possibilitySwitcher.setMinorTickSpacing( 1 );
                // possibilitySwitcher.setMajorTickSpacing(10);
                possibilitySwitcher.addChangeListener( new ChangeListener()
                {
                    @Override
                    public void stateChanged( ChangeEvent evt )
                    {
                        try
                        {
                            int value = possibilitySwitcher.getValue();
                            directChooser.setText( String.format( "%d", value ) );
                            showPossibility( value );
                        }
                        catch ( Exception e )
                        {
                        }
                    }
                } );
            }
            {
                directChooser = new JFormattedTextField( NumberFormat.getNumberInstance() );
                directChooser.setText( "1" );
                directChooser.setHorizontalAlignment( SwingConstants.TRAILING );
                directChooser.addPropertyChangeListener( new PropertyChangeListener()
                {
                    @Override
                    public void propertyChange( PropertyChangeEvent evt )
                    {
                        try
                        {
                            int value = Integer.parseInt( directChooser.getText() );
                            if ( value != possibilitySwitcher.getValue() )
                            {
                                possibilitySwitcher.setValue( value );
                            }
                            showPossibility( value );
                        }
                        catch ( Exception e )
                        {
                        }
                    }
                } );
            }
            {
                ofLabel = new JLabel();
                ofLabel.setText( "of" );
            }
            viewDialog.setSize( 740, 591 );
            viewDialogLayout.setHorizontalGroup( viewDialogLayout.createSequentialGroup().addContainerGap().addGroup( viewDialogLayout.createParallelGroup().addGroup( GroupLayout.Alignment.LEADING,
                                                                                                                                                                       viewDialogLayout.createSequentialGroup().addComponent( directChooser,
                                                                                                                                                                                                                              GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                              69,
                                                                                                                                                                                                                              GroupLayout.PREFERRED_SIZE ).addPreferredGap( LayoutStyle.ComponentPlacement.RELATED ).addComponent( ofLabel,
                                                                                                                                                                                                                                                                                                                                   GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                                   18,
                                                                                                                                                                                                                                                                                                                                   GroupLayout.PREFERRED_SIZE ).addComponent( getMaxPossibilitiesLabel(),
                                                                                                                                                                                                                                                                                                                                                                              GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                                                                              44,
                                                                                                                                                                                                                                                                                                                                                                              GroupLayout.PREFERRED_SIZE ).addPreferredGap( LayoutStyle.ComponentPlacement.UNRELATED ).addGroup( viewDialogLayout.createParallelGroup().addComponent( getLogLabel(),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      GroupLayout.Alignment.LEADING,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      0,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      555,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      Short.MAX_VALUE ).addGroup( GroupLayout.Alignment.LEADING,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  viewDialogLayout.createSequentialGroup().addGap( 0,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   466,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   Short.MAX_VALUE ).addComponent( getCloseButton(),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   89,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   GroupLayout.PREFERRED_SIZE ) ) ) ).addComponent( possibilitySwitcher,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    GroupLayout.Alignment.LEADING,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    0,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    716,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    Short.MAX_VALUE ).addComponent( headline,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    GroupLayout.Alignment.LEADING,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    0,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    716,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    Short.MAX_VALUE ).addComponent( getJScrollPane1(),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    GroupLayout.Alignment.LEADING,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    0,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    716,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    Short.MAX_VALUE ) ).addContainerGap() );
            viewDialogLayout.setVerticalGroup( viewDialogLayout.createSequentialGroup().addContainerGap().addComponent( headline,
                                                                                                                        GroupLayout.PREFERRED_SIZE,
                                                                                                                        15,
                                                                                                                        GroupLayout.PREFERRED_SIZE ).addPreferredGap( LayoutStyle.ComponentPlacement.UNRELATED ).addComponent( possibilitySwitcher,
                                                                                                                                                                                                                               GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                               46,
                                                                                                                                                                                                                               GroupLayout.PREFERRED_SIZE ).addGroup( viewDialogLayout.createParallelGroup().addComponent( getLogLabel(),
                                                                                                                                                                                                                                                                                                                           GroupLayout.Alignment.LEADING,
                                                                                                                                                                                                                                                                                                                           GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                           64,
                                                                                                                                                                                                                                                                                                                           GroupLayout.PREFERRED_SIZE ).addGroup( viewDialogLayout.createSequentialGroup().addGap( 12 ).addGroup( viewDialogLayout.createParallelGroup( GroupLayout.Alignment.BASELINE ).addComponent( directChooser,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       GroupLayout.Alignment.BASELINE,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       GroupLayout.PREFERRED_SIZE ).addComponent( ofLabel,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  GroupLayout.Alignment.BASELINE,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  GroupLayout.PREFERRED_SIZE ).addComponent( getMaxPossibilitiesLabel(),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             GroupLayout.Alignment.BASELINE,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             GroupLayout.PREFERRED_SIZE ) ).addGap( 30 ) ) ).addPreferredGap( LayoutStyle.ComponentPlacement.UNRELATED ).addComponent( getJScrollPane1(),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       0,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       391,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       Short.MAX_VALUE ).addPreferredGap( LayoutStyle.ComponentPlacement.RELATED ).addComponent( getCloseButton(),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 GroupLayout.PREFERRED_SIZE ).addContainerGap() );
        }
        initView();
        return viewDialog;
    }

    public JSlider getPossibilitySwitcher()
    {
        return possibilitySwitcher;
    }

    public JFormattedTextField getDirectChooser()
    {
        return directChooser;
    }

    @Override
    public void bindingDoUnbind()
    {
    }

    @Override
    public AbstractOption getUsedOption()
    {
        return option;
    }

    private JTextArea getLogLabel()
    {
        if ( logLabel == null )
        {
            logLabel = new JTextArea();
            logLabel.setText( "LOG" );
            logLabel.setOpaque( false );
            logLabel.setBorder( BorderFactory.createEmptyBorder( 0, 0, 0, 0 ) );
            logLabel.setEditable( false );
        }
        return logLabel;
    }

    public XmlTextPane getXml()
    {
        if ( xml == null )
        {
            xml = new XmlTextPane();
            xml.setText( "xml" );
        }
        return xml;
    }

    private JScrollPane getJScrollPane1()
    {
        if ( jScrollPane1 == null )
        {
            jScrollPane1 = new JScrollPane();
            jScrollPane1.setViewportView( getXml() );
        }
        return jScrollPane1;
    }

    private JButton getCloseButton()
    {
        if ( closeButton == null )
        {
            closeButton = new JButton();
            closeButton.setText( "Close" );
            closeButton.addActionListener( new ActionListener()
            {
                @Override
                public void actionPerformed( ActionEvent evt )
                {
                    getViewDialog().dispose();
                }
            } );
        }
        return closeButton;
    }

    public JLabel getMaxPossibilitiesLabel()
    {
        if ( maxPossibilitiesLabel == null )
        {
            maxPossibilitiesLabel = new JLabel();
            maxPossibilitiesLabel.setText( "12345" );
        }
        return maxPossibilitiesLabel;
    }

    private void showPossibility( int value )
        throws Exception
    {
        String message = DomUtilities.domToString( wrappingOracle.getPossibility( value - 1 ) );
        getXml().setText( message );
        logLabel.setText( WeaknessLog.representation() );
        logLabel.setSize( logLabel.getPreferredSize() );
    }

    private void createWrappingOracle()
    {
        SignatureManager sm = signateWrappingPlugin.getSignatureManager();
        SchemaAnalyzer sa = signateWrappingPlugin.getUsedSchemaAnalyser();
        wrappingOracle = new WrappingOracle( sm.getDocument(), sm.getPayloads(), sa );
    }

    private void initView()
    {
        int max = wrappingOracle.maxPossibilities();
        if ( max > 0 )
        {
            getPossibilitySwitcher().setMinimum( 1 );
            getPossibilitySwitcher().setMaximum( max + 1 );
            getPossibilitySwitcher().setValue( 1 );
            getPossibilitySwitcher().setMinorTickSpacing( ( max + 1 ) / 10 );
            getMaxPossibilitiesLabel().setText( String.format( "%d", max + 1 ) );
            getPossibilitySwitcher().setEnabled( true );
            getXml().setEnabled( true );
        }
        else
        {
            getPossibilitySwitcher().setMinimum( 0 );
            getPossibilitySwitcher().setMaximum( 0 );
            getPossibilitySwitcher().setMinorTickSpacing( 1 );
            // getMaxPossibilitiesLabel().setText("0");
            getPossibilitySwitcher().setEnabled( false );
            getXml().setText( "No possibilites available" );
            getXml().setEnabled( false );
            logLabel.setText( "" );

        }
    }
}
