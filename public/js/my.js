//###################################
// jQuery function
//###################################
$.fn.textWidth = function(text, font) {
	if (!$.fn.textWidth.fakeEl) $.fn.textWidth.fakeEl = $('<span>').hide().appendTo(document.body);
	$.fn.textWidth.fakeEl.text(text || this.val() || this.text()).css('font', font || this.css('font'));
	return $.fn.textWidth.fakeEl.width();
};

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
	"emptyTable": "Aucun r&eacute;sultat trouv&eacute;"
};

var dt_language_EN = {
	"lengthMenu": 'Show <select>'+
		'<option value="10">10</option>'+
		'<option value="25">25</option>'+
		'<option value="50">50</option>'+
		'<option value="-1">All</option>'+
		'</select> entries',
	"loadingRecords": "Loading data...",
	"emptyTable": "No result found"
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
// Datatable - table
//###################################
function init_dt_rules() {
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
				createdCell: function (td, data, row) {
					if ( row['action'] == 'allow' ) {
						$(td).addClass('cell_green');
						row['enable'] == 0 ? $(td).addClass('cell_bg_disabled') : $(td).addClass('cell_bg_green');
					} else if ( row['action'] == 'drop' || data == 'deny' ) {
						$(td).addClass('cell_red');
						row['enable'] == 0 ? $(td).addClass('cell_bg_disabled') : $(td).addClass('cell_bg_red');
					} else {}
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
				createdCell: function (td, data, row) {
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
			data: dt_rules_ajax_data,
			dataType: 'json',
			dataSrc: function (json) {
				if ( json.error_message ) { alert_message_error(json.error_message); }
				return json.rules;
			},
            error: function (jqXHR) {
				if (jqXHR.status == 403) {			// Unauthenticated
					alert_message_error('Not authenticated, redirecting to login page...');
					window.location.replace('/login');
				} else if ( jqXHR.status == 400 && jqXHR.responseText ) {		// Malformed request
					alert_message_error('Unable to initialize Datatable. Bad request - '+jqXHR.responseText);
				} else if ( jqXHR.status == 0 ) {		// Timeout
					alert_message_error('Unable to initialize Datatable. No answer from server for url '+this.url);
				} else {		// Generic
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
		}
	} );
}

function dt_rules_ajax_data(d) {
	// variables provided in response to a POST query to /home 
	d.fw = dt_rules_data_fw;
	d.rules = dt_rules_data_rules;
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

function clearSelection() {
	if(document.selection && document.selection.empty) {
		document.selection.empty();
	} else if(window.getSelection) {
		var sel = window.getSelection();
		sel.removeAllRanges();
	}
}

function set_auto_columnWidth() {
	var add_width = 5;
	$( '.column_auto' ).each( function() {
		var max_width = 0;
		$(this).children( "span.rank_rule_container" ).each( function() {
			var width = parseInt($(this).textWidth()) + add_width;
			if (width > max_width) { max_width = width; }
		});
		$(this).css({
			'columnWidth': 				max_width+"px",
			'-webkit-column-width':	max_width+"px",
			'-moz-column-width':		max_width+"px"
		});
	});
}

//###################################
// Trace! Button
//###################################
function sendRequest () {
	$.post( '/query', {
			query: $('#TF_input_textarea').val(),
			fw: "test"
		},
		function( data ) {
			$( "#TF_content" ).html( data );
	});
}

$.ajaxSetup({
    error: function (jqXHR) {
        if (jqXHR.status == 403) {					// Unauthenticated
			alert_message_error('Not authenticated, redirecting to login page...');
			window.location.replace('/login');
		} else if ( jqXHR.status == 400 && jqXHR.responseText) {		// Malformed request
			alert_message_error('Bad request. '+jqXHR.responseText);
		} else if ( jqXHR.status == 0 ) {			// Timeout
			alert_message_error('No answer from server for url '+this.url);
        } else {		// Generic
			alert_message_error(jqXHR.status+' '+jqXHR.statusText+' on url '+this.url);
		}
    }
});


//###################################
// Bind event handler
//###################################
function rulesEvents() {
	/**********************
	// Initialize datatable
	**********************/
	init_dt_rules();
	
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
		clearSelection();
	});
	$('#table_rules tbody').on( 'click', 'tr.group', function () {		// collapse rows from given rowgroup on click
		if ( getSelection().toString() ) { return; }		// exit event if click is made for selecting text
		var rows = $(this).nextUntil('.group');
		$(this).next().hasClass('hidden') ?	$(rows).removeClass('hidden') : $(rows).addClass('hidden');
	});
	$('#table_rules tbody').on( 'dblclick', 'tr.group', function () {		// collapse all rowgroups on dblclick
		$(this).next().hasClass('hidden') ?	$('#table_rules tbody tr:not(.group)').addClass('hidden') :
															$('#table_rules tbody tr:not(.group)').removeClass('hidden');
	});
}

function bindEventHandlers() {
	/**********************
	// Text area background
	**********************/
	$('#TF_input_textarea').on( 'input', function() {
		if ( $( this ).hasClass('hidebackground') ) {
			if ( this.value.length == 0 ) {
				$( this ).removeClass('hidebackground');
			}
		} else {
			if ( this.value.length > 0 ) {
				$( this ).addClass('hidebackground');
			}
		}
	});
	
	/**********************
	// Tooltip & popover
	**********************/
	$('[data-toggle="tooltip"]').tooltip();	// for tooltips outside #TF_content
	$('#TF_content').tooltip({
		selector: '[data-toggle="tooltip"]'
	});
	$('#TF_content').on('click', '[data-toggle="popover"], .popover', function(e) {
		console.log('click');
		e.preventDefault();
		return false;
	});
	$('#TF_content').popover({
		selector: '[data-toggle="popover"]',
		trigger: 'focus',
		content: function() {
			return $( '#'+this.id+'_content' ).html();
		},
		html: true
	});
}

//###################################
// On Page ready
//###################################
$(document).ready(function() {		
	bindEventHandlers();
});



