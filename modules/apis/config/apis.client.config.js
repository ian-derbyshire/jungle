'use strict';

// Configuring the Articles module
angular.module('apis').run(['Menus', 'editableOptions',
	function(Menus, editableOptions) {
		// Set top bar menu items
		Menus.addMenuItem('topbar', 'APIs', 'apis', 'dropdown', '/apis(/create)?');
		Menus.addSubMenuItem('topbar', 'apis', 'List APIs', 'apis');
		Menus.addSubMenuItem('topbar', 'apis', 'New API', 'apis/create');
		editableOptions.theme = 'bs3';
	}
]);