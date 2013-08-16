/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
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
package wsattacker.plugin.dos.dosExtension.mvc.view;

import javax.swing.JButton;
import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

/**
 * Sorgt für die Darstellung der Daten auf Bildschirm wie im HTML Format...
 * - jede View = GUI-Element
 * - diese View ist ein ButtonObjekt.. 
 * - Bei Generierung werden mehrere Buttons erzeugt auf Basis dieser Klasse;
 *  
 * AUFRUF/UPDATE IN PHP 
 * - in controller wird render aufgerufen!
 * - ist einzigste Möglichkeit.. gibt nix anderes..  
 * WIE KOMMEN DATEN IN VIEW IN PHP?
 * - als Parameter übergeben bei Render Aufruf!
 * - in View selber durch aufruf von statischen Model Methoden order::doShit();
 * 
 * AUFRUF IN JAVA
 * - Elemente sind einfach da durch laden der GUI
 * UPDATE DER VIEW IN JAVA
 * - jede view implementiert AttackListener 
 *   dadurch kann sich jede View bei Model registrieren und wird bei Änderungen informiert!
 * - da Listener implementiert wird automatisch informiert bei Änderungen 
 *   alles durch Aufruf der Methode: valueChanged(PlusMinusModel model) weiter unten 
 *   hier lese ich aktuelle model Daten aus und aktualisere meine GuiElemente
 * WIE KOMMEN DATEN IN VIEW
 * -  Referenz zu model wird irgendwann übergeben... 
 *    dort liest view alles aus und packt es in GuiElemente
 * 
 * 
 */
@SuppressWarnings("serial")
public class ButtonView extends JButton implements AttackListener
{

    /**
     * Creates a button with no set text or icon.
     */
    public ButtonView() {
        this(null, null, null);
    }    
    
    public ButtonView(AttackModel model, String text, String name )
    {
        super();
		this.setText(text);
		this.setName(name);        
    }

    /**
     * Funktion die aufgerufen wird, wenn sich Model ändert!
     * WICHTIG: 
     * - HIER wird nur ausehen der Buttons manipuliert!! Mehr nicht..
     * - Model wird hier nicht geändert!
     */
    public void valueChanged(AttackModel model)
    {
    	//System.out.println("Sind in valueChangedMethod of ButtonView "+this.getName()+" - while in state: "+model.getCurrentAttackState());
    	
    	// State von Start Button kontrollieren!
        if(this.getName().equals("start") && model.getCurrentAttackState().equals(model.getStateArray()[0]) ){
            setEnabled(true);
        }else  if(this.getName().equals("start")){
            setEnabled(false);
        }
        
       	// State von Finalize Button kontrollieren!
        if(this.getName().equals("finalize") && model.getCurrentAttackState().equals(model.getStateArray()[5]) ){
            setEnabled(true);
        }else if(this.getName().equals("finalize")){
            setEnabled(false);
        }     
        
        // State von AbortButton kontrollieren
        if(this.getName().equals("abort") && (
        		model.getCurrentAttackState().equals(model.getStateArray()[1]) || 
        		model.getCurrentAttackState().equals(model.getStateArray()[2]) ||
        		model.getCurrentAttackState().equals(model.getStateArray()[3]) ||
        		model.getCurrentAttackState().equals(model.getStateArray()[4]) 
        ))
        {
        	setEnabled(true);
        }
        else if(this.getName().equals("abort"))
        {
        	setEnabled(false);
        }
        
    	// State von Close Button kontrollieren!
        if(this.getName().equals("close") && (
        		model.getCurrentAttackState().equals(model.getStateArray()[1]) ||
        		model.getCurrentAttackState().equals(model.getStateArray()[5]) ||
        		model.getCurrentAttackState().equals(model.getStateArray()[6]) ||
        		model.getCurrentAttackState().equals(model.getStateArray()[7]) 
        ))
        {
        	setEnabled(true);
        }
        else if(this.getName().equals("close"))
        {
        	setEnabled(false);
        }   
    }
}
