package org.moonlightcontroller.samples.actions;

public class ActionAlert implements Action {

	private String message;
	
	private ActionAlert(String message) {
		this.message = message;
	}
	
	public String getType() {
		return "Alert";
	}
	
	public String getMessage() {
		return this.message;
	}
	
	public static class Builder implements Action.Builder {

		private String message;
		
		public Builder() {
			
		}
		
		public Builder(String message) {
			this.message = message;
		}
		
		@Override
		public Action build() {
			return new ActionAlert(message);
		}
		
	}
}
