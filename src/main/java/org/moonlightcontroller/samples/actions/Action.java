package org.moonlightcontroller.samples.actions;

public interface Action {

	public String getType(); 
	
	public interface Builder {
		public Action build();
	}
}
