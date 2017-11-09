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
			dataSrc: 'rules',
            error: function (jqXHR) {
				if (jqXHR.status == 403) {			// Unauthenticated
					alert_message_error('Not authenticated, redirecting to login page...');
					window.location.replace('/login');
				} else if ( jqXHR.status == 0 ) {
					alert_message_error('Unable to initialize Datatable. No answer from server for url '+this.url);
				} else {
					alert_message_error('Unable to initialize Datatable. '+jqXHR.status+' '+jqXHR.statusText+' on url '+this.url);
				}
				$('#table_rules tbody > tr > td').first().html('Error: Unable to fetch data...');
            }
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
}


//###################################
// Functions
//###################################
function render_ipaddr_fields ( data, type, row ) {
	var i, j, out = '';
	for (i = 0; i < data.length; ++i) {	// iterate other all fields' elements
		if ( data[i]['type'] == 'ipgroup' || data[i]['type'] == 'ipgroup_with_exclusion' ) {
			out += '<span class="obj_container">';		// BEGIN: group container
			// group name
			out += data[i]['negate'] ? '<div class="obj_group negate">'+data[i]['name']+'</div> ' : '<div class="obj_group">'+data[i]['name']+'</div> ';
			
			// BEGIN: obj content container
			out += '<div class="obj_content_container hidden">';		// BEGIN: obj content container
			
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
				if ( obj ) { out += obj.join(', '); }
				if ( obj_negate ) {
					if ( obj ) { out += ', ' }
					obj_negate.forEach( function(e) {
						out += '<div class="negate">'+e+'</div>, ';
					});
				}
			}
			out += '</div> ';	// END: obj content container
			out += '</span> ';	// END: group container
		} else {
			out += '<span class="obj_container">';
			out += '<div class="obj">'+data[i]['name']+'</div> ';
			out += '<div class="obj_content_container hidden">'+data[i]['value'].join(', ')+'</div> ';
			out += '</span> ';
			// if ( data[i]['name'] == 'Any' ) {
				// out += '<span class="obj_container">';
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
			out += '<span class="obj_container">';		// BEGIN: group container
			// group name
			out += data[i]['negate'] ? '<div class="obj_group negate">'+data[i]['name']+'</div> ' : '<div class="obj_group">'+data[i]['name']+'</div> ';
			
			// BEGIN: obj content container
			out += '<div class="obj_content_container hidden">';		// BEGIN: obj content container
			
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
				if ( obj ) { out += obj.join(', '); }
				if ( obj_negate ) {
					if ( obj ) { out += ', ' }
					obj_negate.forEach( function(e) {
						out += '<div class="negate">'+e+'</div> ';
					});
				}
			}
			out += '</div> ';	// END: obj content container
			out += '</span>';	// END: group container
		} else {
			out += '<span class="obj_container">';
			out += '<div class="obj">'+data[i]['name']+'</div> ';
			out += '<div class="obj_content_container hidden">'+data[i]['value'].join(', ')+'</div> ';
			out += '</span>';
		}
	}
	return out;
}

function alert_message_error (message) {
		if ( $("#TF_errorbox .alert").length >= 4 ) {	// > 5
			$("#TF_errorbox .alert").first().remove();
		} else if ( $("#TF_errorbox .alert").length >= 3 ) {	// > 4
			$("#TF_errorbox .alert").first().dequeue().fadeOut(1000, function () { $(this).remove(); });
		}
		var out = '<div class="alert alert-danger alert-dismissable">';
		out += '<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>';
		out += '<strong>Error:</strong> '+message;
		out += '</div>';
		$('#TF_errorbox').append( out );
		$("#TF_errorbox .alert").last().delay(10000).fadeOut(1000, function () { $(this).remove(); });
		// $("#TF_errorbox .alert").last().hide().fadeIn(200).delay(30000).fadeOut(1000, function () { $(this).remove(); });
}

//###################################
// Trace! Button
//###################################
function sendRequest () {
	$.post( '/home', { query: "test", data: "ok!" }, function( data ) {
		// $( ".result" ).html( data );
	});
	// $.ajax({
		// type: "POST",
		// url: 'home',
		// data: 'query=test',
		// success: success,
		// dataType: dataType
	// });
}

$.ajaxSetup({
    error: function (jqXHR) {
        if (jqXHR.status == 403) {			// Unauthenticated
			alert_message_error('Not authenticated, redirecting to login page...');
			window.location.replace('/login');
		} else if ( jqXHR.status == 0 ) {
			alert_message_error('No answer from server for url '+this.url);
        } else {
			alert_message_error(jqXHR.status+' '+jqXHR.statusText+' on url '+this.url);
		}
    }
});

//###################################
// Bind event handler
//###################################
function bindEventHandlers() {
	/**********************
	// Click event on objects
	**********************/
	$('#table_rules tbody').on("click", ".obj_group, .obj", function(event){		/* on click */
		if ( getSelection().toString() ) { return; }		// exit event if click is made for selecting text
		var obj = $(this).next('.obj_content_container');
		obj.hasClass('hidden') ?	obj.removeClass('hidden') : obj.addClass('hidden');
	});
	$('#table_rules tbody').on("dblclick", "td", function(event){				/* on doubleclick */
		var obj = $(this).find('.obj_content_container');
		obj.first().hasClass('hidden') ?	obj.removeClass('hidden') : obj.addClass('hidden');
	});
	$('#table_rules tbody').on( 'click', 'tr.group', function () {		// collapse rows from given rowgroup on click
		if ( getSelection().toString() ) { return; }		// exit event if click is made for selecting text
		var rows = $(this).nextUntil('.group');
		$(this).next().hasClass('hidden') ?	$(rows).removeClass('hidden') : $(rows).addClass('hidden');
	});
	$('#table_rules tbody').on( 'dblclick', 'tr.group', function () {		// collapse all rowgroups on dblclick
		$(this).next().hasClass('hidden') ?	$('#table_rules tbody tr:not(.group)').removeClass('hidden') :
															$('#table_rules tbody tr:not(.group)').addClass('hidden');
	});
	
	/**********************
	// Alert messages
	**********************/
	
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



