/**
 * Compiled Gutenberg block editor bundle for wm/hinschg-portal.
 */
( function ( wp ) {
	'use strict';
	if ( ! wp || ! wp.blocks || ! wp.element || ! wp.blockEditor || ! wp.components || ! wp.i18n ) {
		return;
	}

	var registerBlockType = wp.blocks.registerBlockType;
	var el = wp.element.createElement;
	var Fragment = wp.element.Fragment;
	var InspectorControls = wp.blockEditor.InspectorControls;
	var useBlockProps = wp.blockEditor.useBlockProps;
	var PanelBody = wp.components.PanelBody;
	var TextControl = wp.components.TextControl;
	var ToggleControl = wp.components.ToggleControl;
	var __ = wp.i18n.__;
	var ServerSideRender = wp.serverSideRender || wp.components.ServerSideRender;

	registerBlockType( 'wm/hinschg-portal', {
		title: __( 'HinSchG Meldestelle Portal', 'wm-hinschg-whistleblower' ),
		description: __( 'Internes Hinweisgeber-Meldeformular und Vorgangsabfrage nach HinSchG.', 'wm-hinschg-whistleblower' ),
		category: 'widgets',
		icon: 'megaphone',
		attributes: {
			title: {
				type: 'string',
				default: 'Interne Meldestelle',
			},
			showDescription: {
				type: 'boolean',
				default: true,
			},
		},
		supports: {
			html: false,
			align: [ 'wide', 'full' ],
		},
		edit: function EditHinSchGPortal( props ) {
			var attributes = props.attributes;
			var setAttributes = props.setAttributes;
			var blockProps = useBlockProps();

			return el(
				Fragment,
				null,
				el(
					InspectorControls,
					null,
					el(
						PanelBody,
						{
							title: __( 'Meldestelle-Einstellungen', 'wm-hinschg-whistleblower' ),
							initialOpen: true,
						},
						el( TextControl, {
							label: __( 'Überschrift', 'wm-hinschg-whistleblower' ),
							value: attributes.title || '',
							onChange: function ( nextTitle ) {
								setAttributes( { title: nextTitle } );
							},
						} ),
						el( ToggleControl, {
							label: __( 'Einleitungstext anzeigen', 'wm-hinschg-whistleblower' ),
							checked: false !== attributes.showDescription,
							onChange: function ( nextVal ) {
								setAttributes( { showDescription: !! nextVal } );
							},
						} )
					)
				),
				el(
					'div',
					blockProps,
					ServerSideRender
						? el( ServerSideRender, {
								block: 'wm/hinschg-portal',
								attributes: attributes,
						  } )
						: el(
								'p',
								null,
								__( 'HinSchG Meldestelle Portal (Vorschau im Frontend).', 'wm-hinschg-whistleblower' )
						  )
				)
			);
		},
		save: function SaveHinSchGPortal() {
			return null;
		},
	} );
} )( window.wp );
