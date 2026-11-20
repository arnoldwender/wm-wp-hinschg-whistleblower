/**
 * Gutenberg block editor script for wm/hinschg-portal.
 *
 * Uses WordPress block-editor globals so zero third-party bundles or CDN calls are needed.
 */
( function ( wp ) {
	if ( ! wp || ! wp.blocks || ! wp.element || ! wp.blockEditor || ! wp.components || ! wp.i18n ) {
		return;
	}

	const { registerBlockType } = wp.blocks;
	const { createElement: el, Fragment } = wp.element;
	const { InspectorControls, useBlockProps } = wp.blockEditor;
	const { PanelBody, TextControl, ToggleControl } = wp.components;
	const { __ } = wp.i18n;
	const ServerSideRender = wp.serverSideRender || wp.components.ServerSideRender;

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
			const { attributes, setAttributes } = props;
			const blockProps = useBlockProps();

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
