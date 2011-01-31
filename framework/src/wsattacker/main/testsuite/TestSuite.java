/*
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2010  Christian Mainka
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package wsattacker.main.testsuite;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlException;

import wsattacker.exception.NotSupportedException;
import wsattacker.main.composition.testsuite.WsdlChangeObserver;

import com.eviware.soapui.impl.WsdlInterfaceFactory;
import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.WsdlProjectFactory;
import com.eviware.soapui.support.SoapUIException;

/**
 * TestSuite for WS-Attacker
 * Provides methods for loading a WSDL and selection operations
 * @author Christian Mainka
 *
 */
public class TestSuite  {
	private static TestSuite instance = new TestSuite();
	Logger log;
	
	WsdlProject project;
	CurrentInterface currentInterface;
	CurrentOperation currentOperation;
	CurrentRequest currentRequest;
	
	List<WsdlChangeObserver> wsdlChangeObserver = new ArrayList<WsdlChangeObserver>();

	public static TestSuite getInstance() {
		return instance;
	}
	
	private TestSuite() {
		log = Logger.getLogger(getClass());
		this.project = createEmptyProject();
		currentInterface = new CurrentInterface(this);
		currentOperation = new CurrentOperation(this);
		currentRequest = new CurrentRequest(this);
	}
	
	// projects are needed for soapui but not for ws-attacker, since we have our own projects
	private WsdlProject createEmptyProject() {
		WsdlProject project = null;
		WsdlProjectFactory fac = new WsdlProjectFactory();
		try {
			project = fac.createNew();
		} catch (XmlException e) {
			log.fatal("Could not Instanciate WsdlProject: " + e.getMessage());
			e.printStackTrace();
		} catch (IOException e) {
			log.fatal("Could not Instanciate WsdlProject: " + e.getMessage());
			e.printStackTrace();
		} catch (SoapUIException e) {
			log.fatal("Could not Instanciate WsdlProject: " + e.getMessage());
			e.printStackTrace();
		}
		return project;
	}
	
	public WsdlProject getProject() {
		return project;
	}

	public void setProject(WsdlProject project) {
		this.project = project;
	}

	public CurrentInterface getCurrentService() {
		return currentInterface;
	}

	public CurrentOperation getCurrentOperation() {
		return currentOperation;
	}

	public CurrentRequest getCurrentRequest() {
		return currentRequest;
	}
	
	public void addCurrentWsdlChangeObserver(WsdlChangeObserver o) {
		wsdlChangeObserver.add(o);
	}
	
	public void removeCurrentWsdlChangeObserver(WsdlChangeObserver o) {
		wsdlChangeObserver.remove(o);
	}
	
	public void notifyCurrentWsdlChangeObservers() {
		for(WsdlChangeObserver o : wsdlChangeObserver) {
			o.wsdlChanged(this);
		}
	}
	
	public void setWsdl(String url) throws SoapUIException, NotSupportedException, Exception {
		assert(this.project != null);
		if( url.length() > 0 )
		{
			// convert string to uri
			if( new File( url ).exists() )
				url = new File( url ).toURI().toURL().toString();

			if( url.toUpperCase().endsWith( "WADL" ) )
				throw new NotSupportedException("WADL not yet supported");
			else {
				importWsdl(url);
			}
		}
	}
	
	private void importWsdl(String url) throws SoapUIException
	{
		WsdlProject project = createEmptyProject();
		WsdlInterfaceFactory.importWsdl( project, url, false ); // import wsdl
		setProject(project);
		notifyCurrentWsdlChangeObservers();
		log.info("Successfully loaded wsdl");
		
	}
}
