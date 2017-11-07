//###################################
// Datatable - LANGUAGE
//###################################
var dt_language_FR = {
	"lengthMenu": 'Afficher <select>'+
		'<option value="10">10</option>'+
		'<option value="25">25</option>'+
		'<option value="50">50</option>'+
		'<option value="-1">All</option>'+
		'</select> &eacute;l&eacute;ments',
	"paginate": {
		"previous": "Pr&eacute;c&eacute;dent",
		"next": "Suivant"
	},
	"zeroRecords":	"Aucun r&eacute;sultat trouv&eacute;",
	"info": "&Eacute;l&eacute;ments <b>_START_</b> &agrave; <b>_END_</b> sur un total de <b>_TOTAL_</b>",
	"infoEmpty": "",
	"search": "Rechercher&nbsp;:",
	"thousands": "",
	"loadingRecords": "Chargement des donn&eacute;es en cours...",
	"infoFiltered":   "(filtr&eacute; sur un total de <b>_MAX_</b>)",
};

var dt_language_EN = {
	"lengthMenu": 'Show <select>'+
		'<option value="10">10</option>'+
		'<option value="25">25</option>'+
		'<option value="50">50</option>'+
		'<option value="-1">All</option>'+
		'</select> entries',
	"loadingRecords": "Loading data..."
};


//###################################
// Datatable - Buttons
//###################################
var dt_button_columns = {
	extend: 'collection',
	text: 'Modifier Colonnes',
	buttons: [ {
		extend: 'columnsToggle',
		columns: ':not([column-togglable="false"])'
	} ],
};

var dt_button_reset_state = {
	text: 'Affichage par Défaut',
	action: function ( e, dt, node, config ) {
		console.log ('Clearing....');
		// clear_footer_search_fields( $(dt.table().node()) );
		dt.state.clear();
		window.location.reload();
	}
};

var dt_button_excel = {
	extend: 'excel',
	exportOptions: {
		columns: ':visible',
		modifier : {
			order:  'current',
			page:   'all',
			search: 'applied'
		}
	}
};

var dt_button_csv = {
	extend: 'csv',
	exportOptions: {
		columns: ':visible',
		modifier : {
			order:  'current',
			page:   'all',
			search: 'applied'
		}
	}
};


//###################################
// Bind event handler
//###################################
function init_dataTables() {
	var table = $('#table_rules').DataTable( {
		// order: [[ 0, "asc" ]],
		aaSorting: [],	// do not sort by default
		ordering: false,	// disable sortering on columns
		stripeClasses: [],
		language: dt_language_EN,
		responsive: false,
		pageLength: 10,
		// stateSave: true,
		// stateDuration: 3600 * 2,
		// stateLoadParams: fill_footer_search_fields_after_state_load,
		colReorder: {
			fixedColumnsLeft: 1
		},
		rowGroup: {
            dataSrc: 'section'
        },
		columns: [
			{
				data: "seq",
				render: function ( data ) {
					return '<div class="headers_row">'+data+'</div>';
				},
				className: 'cell_center'
			},{
				data: "enable",
				render: function ( data ) {
					return data ? 'true' : 'false';
				},
				className: 'cell_center',
				visible: false
			},{
				data: "action",
				createdCell: function (td, data) { 
					if ( data == 'allow' ) {
						$(td).addClass('cell_green');
					} else if ( data == 'drop' || data == 'deny' ) {
						$(td).addClass('cell_red');
					} else {}
				},
				className: 'cell_center',
				visible: false
			},{
				data: "logging",
				render: function ( data ) {
					return data ? 'true' : 'false';
				},
				className: 'cell_center',
				visible: false
			},{
				data: "src",
				render: render_ipaddr_fields
			},{
				data: "dst",
				render: render_ipaddr_fields
			},{
				data: "service",
				render: render_service_fields
			},{
				data: "comment",
				visible: false
			}
		],
		dom: 'lBfrtip',
		buttons: [ dt_button_csv, dt_button_excel, dt_button_columns, dt_button_reset_state ],
		ajax: {
			url: '/API/rules',
			type: 'POST',
			data: function ( d ) {
				d.fw = 'test';
			},
			dataSrc: 'rules'
		},
		createdRow: function (row, data) {
			// Enable values: 0=disabled, 1=enabled
			// Action values: allow, drop, deny
			if ( data['enable'] == 0 ) {
				$(row).addClass('row_disabled');
			} else if ( data['action'] == 'allow' ) {
				$(row).addClass('row_green');
			} else if ( data['action'] == 'drop' || data['action'] == 'deny' ) {
				$(row).addClass('row_red');
			} else {
				$(row).addClass('row_hoverhighlight');
			}
			$(row).addClass( 'toggle_section_'+data['section'].replace(/[^a-zA-Z0-9_-]/g,'_') );
		}
	} );
	$('#table_rules tbody').on( 'click', 'tr.group', function () {		// collapse rows from given rowgroup on click
		var rows = $(this).nextUntil('.group');
		if ( $(this).next().hasClass('hidden') ) {
			$(rows).removeClass('hidden');
		} else {
			$(rows).addClass('hidden');
		}
	});
	$('#table_rules tbody').on( 'dblclick', 'tr.group', function () {		// collapse all rowgroups on dblclick
		if ( $(this).next().hasClass('hidden') ) {
			$('#table_rules tbody tr:not(.group)').removeClass('hidden');
		} else {
			$('#table_rules tbody tr:not(.group)').addClass('hidden');
		}
	});
}


//###################################
// Functions
//###################################
function render_ipaddr_fields ( data, type, row ) {
	var i, j, out = '';
	for (i = 0; i < data.length; ++i) {	// iterate other all fields' elements
		if ( data[i]['type'] == 'ipgroup' || data[i]['type'] == 'ipgroup_with_exclusion' ) {
			out += '<span class="obj_group_container">';		// BEGIN: group container
			// group name
			out += data[i]['negate'] ? '<div class="obj_group negate">'+data[i]['name']+'</div> ' : '<div class="obj_group">'+data[i]['name']+'</div> ';
			// subgroups from group
			if ( data[i]['content_groups'] ) {
				data[i]['content_groups'].forEach( function(e) {
					out += '<div class="obj_subgroup">'+e+'</div> ';
				});
			}
			if ( data[i]['content_groups_negate'] ) {
				data[i]['content_groups_negate'].forEach( function(e) {
					out += '<div class="obj_subgroup negate">'+e+'</div> ';
				});				
			}
			// content from group
			var obj = data[i]['content'], obj_negate = data[i]['content_negate'];
			if ( obj || obj_negate ) {
				if ( obj ) { out += '<div class="obj_content_container">'+obj.join(', '); }
				if ( obj && obj_negate ) { out += ', ' }
				if ( obj_negate ) { 
					obj_negate.forEach( function(e) {
						out += '<div class="negate">'+e+'</div>, ';
					});
				}
				out += '</div>';
			}
			out += '</span>';	// END: group container
		} else {
			out += '<span class="obj_group_container">';
			out += '<div class="obj">'+data[i]['name']+'</div> ';
			out += '<div class="obj_content_container">'+data[i]['value'].join(', ')+'</div>';
			out += '</span>';
			// if ( data[i]['name'] == 'Any' ) {
				// out += '<span class="obj_group_container">';
				// out += '<div class="obj">'+data[i]['name']+'</div>';
				// out += '<div class="obj_content_container">'+data[i]['value'].join(', ')+'</div>';
			// } else {
				// var negate = data[i]['negate'] ? ' negate' : '';
				// data[i]['value'].forEach( function(e) {
					// out += '<div class="obj'+negate+'">'+e+'</div>';
				// });
			// }
		}
	}
	return out;
}

function render_service_fields ( data, type, row ) {
	var i, j, out = '';
	for (i = 0; i < data.length; ++i) {	// iterate other all fields' elements
		if ( data[i]['type'] == 'servicegroup' || data[i]['type'] == 'servicegroup_with_exclusion' ) {
			out += '<span class="obj_group_container">';		// BEGIN: group container
			// group name
			out += data[i]['negate'] ? '<div class="obj_group negate">'+data[i]['name']+'</div> ' : '<div class="obj_group">'+data[i]['name']+'</div> ';
			// subgroups from group
			if ( data[i]['content_groups'] ) {
				data[i]['content_groups'].forEach( function(e) {
					out += '<div class="obj_subgroup">'+e+'</div> ';
				});
			}
			if ( data[i]['content_groups_negate'] ) {
				data[i]['content_groups_negate'].forEach( function(e) {
					out += '<div class="obj_subgroup negate">'+e+'</div>';
				});				
			}
			// content from group
			var obj = data[i]['content'], obj_negate = data[i]['content_negate'];
			if ( obj || obj_negate ) {
				if ( obj ) { out += '<div class="obj_content_container">'+obj.join(', '); }
				if ( obj && obj_negate ) { out += ', ' }
				if ( obj_negate ) { 
					obj_negate.forEach( function(e) {
						out += '<div class="negate">'+e+'</div> ';
					});
				}
				out += '</div>';
			}
			out += '</span>';	// END: group container
		} else {
			out += '<span class="obj_group_container">';
			out += '<div class="obj">'+data[i]['name']+'</div> ';
			out += '<div class="obj_content_container">'+data[i]['value'].join(', ')+'</div>';
			out += '</span>';
		}
	}
	return out;
}


//###################################
// Bind event handler
//###################################
function bindEventHandlers() {

	
	
	
	/**********************
	// Tooltip
	**********************/
	$('[data-toggle="tooltip"]').tooltip();
}

//###################################
// On Page ready
//###################################
$(document).ready(function() {
	init_dataTables();
	bindEventHandlers();
});



