package org.moonlightcontroller.samples.actions;

public class ActionDrop implements Action {

	public ActionDrop() {
		
	}
	
	public String getType() {
		return "Drop";
	}
	
	public static class Builder implements Action.Builder {

		@Override
		public Action build() {
			return new ActionDrop();
		}
		
	}
}
