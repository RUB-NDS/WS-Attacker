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

package wsattacker.main.composition.plugin;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;

import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.main.plugin.PluginOptionContainer;
import wsattacker.main.plugin.PluginState;
import wsattacker.main.plugin.result.Result;
import wsattacker.main.plugin.result.ResultEntry;
import wsattacker.main.plugin.result.ResultLevel;
import wsattacker.main.testsuite.TestSuite;


public abstract class AbstractPlugin implements
		SuccessInterface, PluginOptionValueObserver, Comparable<AbstractPlugin>, Serializable {
	
	private static final long serialVersionUID = 1L;

	private int currentPoints;
	private PluginState state;
	private PluginOptionContainer options;
	transient private Set<PluginObserver> observers;
	transient private Logger log;

	/**
	 * Creates a new Plugin, needs an OptionFactory for creating PluginOptions
	 * 
	 * @param optionFactory
	 */
	public AbstractPlugin() {
		options =  new PluginOptionContainer();
		options.addPluginValueContainerObserver(this);
		observers =  new HashSet<PluginObserver>();
		currentPoints = 0;
		state = PluginState.Not_Configured;
		log = Logger.getLogger(getClass());
	}
	
	public abstract void initializePlugin();

	/**
	 * returns the plugin name
	 * 
	 * @return String
	 */
	public abstract String getName();

	/**
	 * returns a plugin description
	 * 
	 * @return String
	 */
	public abstract String getDescription();
	
	/**
	 * returns the plugin author
	 * @return
	 */
	public abstract String getAuthor();

	/**
	 * returns the plugin version
	 */
	public abstract String getVersion();
	
	/**
	 * Returns a container with all needed options
	 * 
	 * @return PluginOptionContainer
	 */
	final public PluginOptionContainer getPluginOptions() {
		return options;
	}

	/***
	 * @return the maximum number of possible points
	 */
	public abstract int getMaxPoints();
	
	/**
	 * returns the currently reached number of points this will be used at the
	 * end to calculate, how successful an attack was
	 * 
	 * @return currently reached number of points
	 */
	final public int getCurrentPoints() {
		return this.currentPoints;
	}
	
	/**
	 * Set the current points to the specified number
	 * @param points
	 */
	final protected void setCurrentPoints(int points) {
		if(points <= getMaxPoints()) {
			this.currentPoints = points;
			notifyCurrentPointsChanged(points);
		}
	}
	
	/**
	 * Increase current points by one
	 */
	final protected void addOnePoint() {
		setCurrentPoints(getCurrentPoints() + 1);
	}
	
	/**
	 * Returns the plugin state
	 * @return the state
	 */
	final public PluginState getState() {
		return state;
	}
	
	/**
	 * Sets the plugin state
	 */
	final protected void setState(PluginState state) {
		if(this.state != state) {
			PluginState oldState = this.state;
			this.state = state;
			notifyPluginStateChagend(state, oldState);
		}
	}
	
	/**
	 * A wrapper function for easy logging using log4j
	 * @param level
	 * @param content
	 */
	final protected Logger log() {
		return log;
	}
	
	/**
	 * A wrapper function for easy making results
	 * @param level
	 * @param content
	 */
	final protected void result(ResultLevel level, String content) {
		Result.getGlobalResult().add(new ResultEntry(level, getName(), content));
	}

	/**
	 * A wrapper function for easy making a critical result
	 * @param content
	 */
	final protected void critical(String content) {
		result(ResultLevel.Critical, content);
	}
	/**
	 * A wrapper function for easy making important results
	 * This should be only a few, e.g. conclusion
	 * @param content
	 */
	final protected void important(String content) {
		result(ResultLevel.Important, content);
	}

	/**
	 * A wrapper function for easy making info results
	 * This can be status information, e.g. what the plugins does at the moment
	 * @param content
	 */
	final protected void info(String content) {
		result(ResultLevel.Info, content);
	}

	/**
	 * A wrapper function for easy tracing
	 * This can contain request contents or any internals
	 * @param content
	 */
	final protected void trace(String content) {
		result(ResultLevel.Trace, content);
	}

	/***
	 * returns whether the attack is running
	 * 
	 * @return is the attack running? true/false
	 */
	final public boolean isRunning() {
		return (state == PluginState.Running);
	}
	
	/***
	 * return whether the plugin is ready to run
	 * or still need some configuration
	 * @return boolean ready
	 */
	final public boolean isReady() {
		return (state == PluginState.Ready);
	}
	
	/***
	 * return whether the plugin is finished
	 * @return boolean finished
	 */
	final public boolean isFinished() {
		return (state == PluginState.Finished);
	}
	
	/***
	 * return whether the plugin is finished
	 * @return boolean finished
	 */
	final public boolean isFailed() {
		return (state == PluginState.Failed);
	}
	
	/***
	 * return whether the plugin is requested to abort by the user
	 * @return boolean finished
	 */
	final public boolean isAborting() {
		return (state == PluginState.Aborting);
	}
	
	/***
	 * return whether the plugin is stopped by the user
	 * @return boolean finished
	 */
	final public boolean isStopped() {
		return (state == PluginState.Stopped);
	}
	
	/***
	 * starts the Attack
	 * 
	 * @return wasSuccessfull() or false, if plugin not ready
	 */

	final public boolean startAttack() {
		Logger log = Logger.getLogger(getClass());
		RequestResponsePair original = TestSuite.getInstance().getCurrentRequest();
		if(!isReady()) {
			log.warn(getName() + " is not READY");
			return false;
		}
		if(original.getWsdlRequest() == null) {
			log.warn("There is no current request!");
			return false;
		}
		if(original.getWsdlResponse() == null) {
			log.warn("There is no current response!");
			return false;
		}
		// initiate running
		clean();
		setState(PluginState.Running);
		// start attack hook
		attackImplementationHook(original);
		// if the plugin author forgot to set PluginState
		if ( isRunning()) {
			setState(PluginState.Finished);
		}
		return wasSuccessful();
	}
	
	/***
	 * Implement your Attack here
	 * Note: Do not edit the request response pair
	 * Take it as in information pool.
	 * If you want to send exactly the same request, you have to copy it!
	 * @param request
	 */
	protected abstract void attackImplementationHook(final RequestResponsePair original);

	/***
	 * This method will be called if a new project ist started
	 * and will also be called first in startAttack()
	 * 
	 * E.g. for simplest implementation: setCurrentPoints(0)
	 */
	public abstract void clean();
	
	/**
	 * This method will be called to abort the attack
	 * It sets the plugin state to "Aborting" so use
	 * the isAborting() method in your code.
	 */
	final public void abortAttack() {
		setState(PluginState.Aborting);
	}
	
	/**
	 * Sets the plugin state to "Stopped";
	 * Afterwards, stopHook() is called.
	 */
	final public void stopAttack() {
		stopHook();
		setState(PluginState.Stopped);
	}
	
	/**
	 * This method will be called after the attack thread is killed.
	 * The plugin can try to clean up everything, what could not be 
	 * finished in the abortHook().
	 * The default implementation does nothing.
	 */
	protected void stopHook() {
		
	}
	
	/***
	 * returns whether the attack was successful should return false if attack
	 * is not finished your implementation must decide, how many points must be
	 * reached for an successful attack
	 * 
	 * @return true if finished and successful
	 */
	public abstract boolean wasSuccessful();
	
	final public void addPluginObserver(PluginObserver o) {
		observers.add(o);
	}
	
	final public void removePluginObserver(PluginObserver o) {
		observers.remove(o);
	}
	
	private void notifyCurrentPointsChanged(int points) {
		for(PluginObserver o : observers) {
			o.currentPointsChanged(this, points);
		}
	}
	
	private void notifyPluginStateChagend(PluginState newState,  PluginState oldState) {
		for(PluginObserver o : observers) {
			o.pluginStateChanged(this, newState, oldState);
		}
	}
	
	/***
	 * This method can be used to test, if a plugin is configured correctly
	 * So you might change the Plugin.STATE from NOT_CONFIGURED to READY here,
	 * depending on correctly set options (and of course you should change 
	 * state back, if options are not correct) all user changes in options 
	 * will call this method
	 */
	@Override
	public void optionValueChanged(AbstractOption option) {
		
	}
	
	/***
	 * This method will be used to restore saved plugin configuration.
	 * The current implementation will only work for very basic plugins:
	 * 
	 * for each plugin option from $plugin
	 * 		set the corresponding option to the same value
	 * 
	 * You have to override this method if you use special options, e.g.
	 * options which depend on the current wsdl or if your plugin uses dynamic
	 * options (e.g. getPluginOptions() will not return every plugin option).
	 * @param plugin
	 */
	public void restoreConfiguration(AbstractPlugin plugin) {
		for(AbstractOption savedOption : plugin.getPluginOptions()) {
			AbstractOption currentOption = getPluginOptions().getByName(savedOption.getName());
			String savedValue = savedOption.getValueAsString();
			if( currentOption != null) {
				if(currentOption.isValid(savedValue)) {
					currentOption.parseValue(savedValue);
					Logger.getLogger(getClass()).info(String.format("Restored option %s=%s", savedOption.getName(), savedOption.getValueAsString()));
				}
				else {
					Logger.getLogger(getClass()).info("Could not restore Value '" + savedValue + "' for Option '" + savedOption.getName() + "' - The value is not valid!");
				}
			} else {
				Logger.getLogger(getClass()).error("The Option '" + savedOption.getName() + "' is not present in this plugin. Contact the plugin author.");
			}
		}
	}
	
	public abstract String[] getCategory();

	/***
	 * Two plugins are equal, if the have the same name
	 */
	@Override
	public boolean equals(Object o) {
		if (!(o instanceof AbstractPlugin))
			return false;
		return ((AbstractPlugin)o).getName().equals(this.getName());
	}
	
//	/***
//	 * As we override equals(...), we also have to override hashCode()
//	 * TODO: Fix why this ends up in an error
//	 */
//	@Override
//	public int hashCode() {
//		return getName().hashCode();
//	}
	
	@Override
	public int compareTo(AbstractPlugin p) {
		return getName().compareTo(p.getName());
	}

	@Override
	public String toString() {
		return getName();
	}
}
