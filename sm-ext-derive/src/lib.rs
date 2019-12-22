extern crate proc_macro;

use proc_macro2::{Delimiter, Group, Ident, Literal, Punct, Spacing, Span, TokenStream, TokenTree};
use quote::{format_ident, quote, quote_spanned, ToTokens, TokenStreamExt};
use syn;
use syn::spanned::Spanned;

/// Creates the entry point for SourceMod to recognise this library as an extension and set the required metadata.
///
/// The `#[extension]` attribute recognises the following optional keys using the *MetaListNameValueStr* syntax:
///   * `name`
///   * `description`
///   * `url`
///   * `author`
///   * `version`
///   * `tag`
///   * `date`
///
/// If not overridden, all extension metadata will be set to suitable values using the Cargo package metadata.
///
/// An instance of the struct this is applied to will be created with [`Default::default()`] to serve
/// as the global singleton instance, and you can implement the [`IExtensionInterface`] trait on the
/// type to handle SourceMod lifecycle callbacks.
#[proc_macro_derive(SMExtension, attributes(extension))]
pub fn derive_extension_metadata(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).unwrap();

    let name = &ast.ident;
    let input = MetadataInput::new(&ast);

    let extension_name = CStringToken(input.name);
    let extension_description = CStringToken(input.description);
    let extension_url = CStringToken(input.url);
    let extension_author = CStringToken(input.author);
    let extension_version = CStringToken(input.version);
    let extension_tag = CStringToken(input.tag);
    let extension_date = CStringToken(input.date);

    let expanded = quote! {
        // TODO: Checking for a test build here doesn't work when a dependent crate is being tested.
        #[cfg(all(windows, not(target_feature = "crt-static"), not(test)))]
        compile_error!("SourceMod requires the Windows CRT to be statically linked (pass `-C target-feature=+crt-static` to rustc)");

        #[no_mangle]
        pub extern "C" fn GetSMExtAPI() -> *mut ::sm_ext::IExtensionInterfaceAdapter<#name> {
            let delegate: #name = Default::default();
            let extension = ::sm_ext::IExtensionInterfaceAdapter::new(delegate);
            Box::into_raw(Box::new(extension))
        }

        impl ::sm_ext::IExtensionMetadata for #name {
            fn get_extension_name(&self) -> &'static ::std::ffi::CStr {
                #extension_name
            }
            fn get_extension_url(&self) -> &'static ::std::ffi::CStr {
                #extension_url
            }
            fn get_extension_tag(&self) -> &'static ::std::ffi::CStr {
                #extension_tag
            }
            fn get_extension_author(&self) -> &'static ::std::ffi::CStr {
                #extension_author
            }
            fn get_extension_ver_string(&self) -> &'static ::std::ffi::CStr {
                #extension_version
            }
            fn get_extension_description(&self) -> &'static ::std::ffi::CStr {
                #extension_description
            }
            fn get_extension_date_string(&self) -> &'static ::std::ffi::CStr {
                #extension_date
            }
        }
    };

    expanded.into()
}

struct CStringToken(MetadataString);

impl ToTokens for CStringToken {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let value = match &self.0 {
            MetadataString::String(str) => str.to_token_stream(),
            MetadataString::EnvVar(var) => quote! {
                env!(#var)
            },
        };

        // Inspired by https://crates.io/crates/c_str_macro
        tokens.append_all(quote! {
            unsafe {
                ::std::ffi::CStr::from_ptr(concat!(#value, "\0").as_ptr() as *const ::std::os::raw::c_char)
            }
        });
    }
}

enum MetadataString {
    String(String),
    EnvVar(String),
}

struct MetadataInput {
    pub name: MetadataString,
    pub description: MetadataString,
    pub url: MetadataString,
    pub author: MetadataString,
    pub version: MetadataString,
    pub tag: MetadataString,
    pub date: MetadataString,
}

impl MetadataInput {
    #[allow(clippy::cognitive_complexity)]
    pub fn new(ast: &syn::DeriveInput) -> MetadataInput {
        let mut name = None;
        let mut description = None;
        let mut url = None;
        let mut author = None;
        let mut version = None;
        let mut tag = None;
        let mut date = None;

        let meta = ast.attrs.iter().find_map(|attr| match attr.parse_meta() {
            Ok(m) => {
                if m.path().is_ident("extension") {
                    Some(m)
                } else {
                    None
                }
            }
            Err(e) => panic!("unable to parse attribute: {}", e),
        });

        if let Some(meta) = meta {
            let meta_list = match meta {
                syn::Meta::List(inner) => inner,
                _ => panic!("attribute 'extension' has incorrect type"),
            };

            for item in meta_list.nested {
                let pair = match item {
                    syn::NestedMeta::Meta(syn::Meta::NameValue(ref pair)) => pair,
                    _ => panic!("unsupported attribute argument {:?}", item.to_token_stream()),
                };

                if pair.path.is_ident("name") {
                    if let syn::Lit::Str(ref s) = pair.lit {
                        name = Some(s.value());
                    } else {
                        panic!("name value must be string literal");
                    }
                } else if pair.path.is_ident("description") {
                    if let syn::Lit::Str(ref s) = pair.lit {
                        description = Some(s.value())
                    } else {
                        panic!("description value must be string literal");
                    }
                } else if pair.path.is_ident("url") {
                    if let syn::Lit::Str(ref s) = pair.lit {
                        url = Some(s.value())
                    } else {
                        panic!("url value must be string literal");
                    }
                } else if pair.path.is_ident("author") {
                    if let syn::Lit::Str(ref s) = pair.lit {
                        author = Some(s.value())
                    } else {
                        panic!("author value must be string literal");
                    }
                } else if pair.path.is_ident("version") {
                    if let syn::Lit::Str(ref s) = pair.lit {
                        version = Some(s.value())
                    } else {
                        panic!("version value must be string literal");
                    }
                } else if pair.path.is_ident("tag") {
                    if let syn::Lit::Str(ref s) = pair.lit {
                        tag = Some(s.value())
                    } else {
                        panic!("tag value must be string literal");
                    }
                } else if pair.path.is_ident("date") {
                    if let syn::Lit::Str(ref s) = pair.lit {
                        date = Some(s.value())
                    } else {
                        panic!("date value must be string literal");
                    }
                } else {
                    panic!("unsupported attribute key '{}' found", pair.path.to_token_stream())
                }
            }
        }

        let name = match name {
            Some(name) => MetadataString::String(name),
            None => MetadataString::EnvVar("CARGO_PKG_NAME".into()),
        };

        let description = match description {
            Some(description) => MetadataString::String(description),
            None => MetadataString::EnvVar("CARGO_PKG_DESCRIPTION".into()),
        };

        let url = match url {
            Some(url) => MetadataString::String(url),
            None => MetadataString::EnvVar("CARGO_PKG_HOMEPAGE".into()),
        };

        // TODO: This probably needs a special type to post-process the author list later.
        let author = match author {
            Some(author) => MetadataString::String(author),
            None => MetadataString::EnvVar("CARGO_PKG_AUTHORS".into()),
        };

        let version = match version {
            Some(version) => MetadataString::String(version),
            None => MetadataString::EnvVar("CARGO_PKG_VERSION".into()),
        };

        let tag = match tag {
            Some(tag) => MetadataString::String(tag),
            None => MetadataString::EnvVar("CARGO_PKG_NAME".into()),
        };

        let date = match date {
            Some(date) => MetadataString::String(date),
            None => MetadataString::String("with Rust".into()),
        };

        MetadataInput { name, description, url, author, version, tag, date }
    }
}

#[proc_macro_derive(SMInterfaceApi, attributes(interface))]
pub fn derive_interface_api(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    let ident = input.ident;

    let attribute = input.attrs.iter().find_map(|attr| match attr.parse_meta() {
        Ok(m) => {
            if m.path().is_ident("interface") {
                Some(m)
            } else {
                None
            }
        }
        Err(e) => panic!("unable to parse attribute: {}", e),
    });

    let mut output = TokenStream::new();

    if let Some(attribute) = attribute {
        let nested = match attribute {
            syn::Meta::List(inner) => inner.nested,
            _ => panic!("attribute 'interface' has incorrect type"),
        };

        if nested.len() != 2 {
            panic!("attribute 'interface' expected 2 params: name, version")
        }

        let interface_name = match &nested[0] {
            syn::NestedMeta::Lit(lit) => match lit {
                syn::Lit::Str(str) => str,
                _ => panic!("attribute 'interface' param 1 should be a string"),
            },
            _ => panic!("attribute 'interface' param 1 should be a literal string"),
        };

        let interface_version = match &nested[1] {
            syn::NestedMeta::Lit(lit) => match lit {
                syn::Lit::Int(int) => int,
                _ => panic!("attribute 'interface' param 2 should be an integer"),
            },
            _ => panic!("attribute 'interface' param 2 should be a literal integer"),
        };

        output.extend(quote! {
            impl RequestableInterface for #ident {
                fn get_interface_name() -> &'static str {
                    #interface_name
                }

                fn get_interface_version() -> u32 {
                    #interface_version
                }

                #[allow(clippy::transmute_ptr_to_ptr)]
                unsafe fn from_raw_interface(iface: SMInterface) -> #ident {
                    #ident(std::mem::transmute(iface.0))
                }
            }
        });
    }

    output.extend(quote! {
        impl SMInterfaceApi for #ident {
            fn get_interface_version(&self) -> u32 {
                unsafe { virtual_call!(GetInterfaceVersion, self.0) }
            }

            fn get_interface_name(&self) -> &str {
                unsafe {
                    let c_name = virtual_call!(GetInterfaceName, self.0);

                    CStr::from_ptr(c_name).to_str().unwrap()
                }
            }

            fn is_version_compatible(&self, version: u32) -> bool {
                unsafe { virtual_call!(IsVersionCompatible, self.0, version) }
            }
        }
    });

    output.into()
}

/// Declares a function as a native callback and generates internal support code.
///
/// A valid native callback must be a free function that is not async, not unsafe, not extern, has
/// no generic parameters, the first argument takes a [`&IPluginContext`](IPluginContext), any
/// remaining arguments are convertible to [`cell_t`] using [`TryIntoPlugin`] (possibly wrapped in
/// an [`Option`]), and returns a type that satisfies the [`NativeResult`] trait.
///
/// When the native is invoked by SourceMod the input arguments will be checked to ensure all required
/// arguments have been passed and are of the correct type, and panics or error results will automatically
/// be converted into a SourceMod native error using [`safe_native_invoke`].
///
/// # Example
///
/// ```
/// use sm_ext::{native, IPluginContext};
///
/// #[native]
/// fn simple_add_native(_ctx: &IPluginContext, a: i32, b: i32) -> i32 {
///     a + b
/// }
/// ```
#[proc_macro_attribute]
pub fn native(_attr: proc_macro::TokenStream, item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let mut input = syn::parse_macro_input!(item as syn::ItemFn);
    // println!("{:#?}", input);

    let mut output = TokenStream::new();

    if let Some(asyncness) = &input.sig.asyncness {
        let span = asyncness.span();
        output.extend(error("Native callback must not be async", span, span));
    }

    if let Some(unsafety) = &input.sig.unsafety {
        let span = unsafety.span();
        output.extend(error("Native callback must not be unsafe", span, span));
    }

    if let Some(abi) = &input.sig.abi {
        let span = abi.span();
        output.extend(error("Native callback must use the default Rust ABI", span, span));
    }

    if !input.sig.generics.params.is_empty() {
        let span = input.sig.generics.span();
        output.extend(error("Native callback must not have any generic parameters", span, span));
    }

    let mut param_count: i32 = 0;
    let mut trailing_optional_count = 0;
    let mut param_output = TokenStream::new();
    for param in &input.sig.inputs {
        match param {
            syn::FnArg::Receiver(param) => {
                let span = param.span();
                output.extend(error("Native callback must not be a method", span, span));
            }
            syn::FnArg::Typed(param) => {
                param_count += 1;
                if param_count == 1 {
                    param_output.extend(quote_spanned!(param.span() => &ctx,));
                    continue;
                }

                let mut is_optional = false;
                if let syn::Type::Path(path) = &*param.ty {
                    if path.path.segments.last().unwrap().ident == "Option" {
                        is_optional = true;
                        trailing_optional_count += 1;
                    } else {
                        trailing_optional_count = 0;
                    }
                } else {
                    trailing_optional_count = 0;
                }

                let param_idx = param_count - 1;
                let convert_param = quote_spanned!(param.span() =>
                    (*(args.offset(#param_idx as isize)))
                        .try_into_plugin(&ctx)
                        .map_err(|err| format!("Error processing argument {}: {}", #param_idx, err))?
                );

                if is_optional {
                    param_output.extend(quote! {
                        if #param_idx <= count {
                            Some(#convert_param)
                        } else {
                            None
                        },
                    });
                } else {
                    param_output.extend(quote! {
                        #convert_param,
                    });
                }
            }
        };
    }

    let args_minimum = (param_count - 1) - trailing_optional_count;
    let wrapper_ident = &input.sig.ident;
    let callback_ident = format_ident!("__{}_impl", wrapper_ident);
    output.extend(quote! {
        unsafe extern "C" fn #wrapper_ident(ctx: sm_ext::IPluginContextPtr, args: *const sm_ext::cell_t) -> sm_ext::cell_t {
            let ctx = sm_ext::IPluginContext(ctx);

            sm_ext::safe_native_invoke(&ctx, || -> Result<sm_ext::cell_t, Box<dyn std::error::Error>> {
                use sm_ext::NativeResult;
                use sm_ext::TryIntoPlugin;

                let count: i32 = (*args).into();
                if count < #args_minimum {
                    return Err(format!("Not enough arguments, got {}, expected at least {}", count, #args_minimum).into());
                }

                let result = #callback_ident(
                    #param_output
                ).into_result()?;

                Ok(result.try_into_plugin(&ctx)
                    .map_err(|err| format!("Error processing return value: {}", err))?)
            })
        }
    });

    input.sig.ident = callback_ident;
    output.extend(input.to_token_stream());

    // println!("{}", output.to_string());

    output.into()
}

#[proc_macro_attribute]
pub fn vtable(attr: proc_macro::TokenStream, item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let this_ptr_type = syn::parse_macro_input!(attr as syn::Path);
    let mut input = syn::parse_macro_input!(item as syn::ItemStruct);
    let mut output = TokenStream::new();

    // println!("{}", input.to_token_stream().to_string());

    input.attrs.push(syn::parse_quote!(#[doc(hidden)]));
    input.attrs.push(syn::parse_quote!(#[repr(C)]));

    let mut did_error = false;
    for field in &mut input.fields {
        if let syn::Type::BareFn(ty) = &mut field.ty {
            ty.unsafety = syn::parse_quote!(unsafe);
            ty.abi = syn::parse_quote!(extern "C");

            // Prepend the thisptr argument
            ty.inputs.insert(0, syn::parse_quote!(this: #this_ptr_type));
        } else {
            let span = field.span();
            output.extend(error("All vtable struct fields must be bare functions", span, span));
            did_error = true;
        }
    }

    if !did_error {
        input.attrs.push(syn::parse_quote!(#[cfg(not(all(windows, target_arch = "x86")))]));
    }

    output.extend(input.to_token_stream());

    if did_error {
        return output.into();
    }

    input.attrs.pop();
    input.attrs.push(syn::parse_quote!(#[cfg(all(windows, target_arch = "x86", feature = "thiscall"))]));

    for field in &mut input.fields {
        if let syn::Type::BareFn(ty) = &mut field.ty {
            if ty.variadic.is_none() {
                ty.abi = syn::parse_quote!(extern "thiscall");
            }
        }
    }

    output.extend(input.to_token_stream());

    input.attrs.pop();
    input.attrs.push(syn::parse_quote!(#[cfg(all(windows, target_arch = "x86", not(feature = "thiscall")))]));

    for field in &mut input.fields {
        if let syn::Type::BareFn(ty) = &mut field.ty {
            if ty.variadic.is_none() {
                ty.abi = syn::parse_quote!(extern "fastcall");

                // Add a dummy argument to be passed in edx
                ty.inputs.insert(1, syn::parse_quote!(_dummy: *const usize));
            }
        }
    }

    output.extend(input.to_token_stream());

    // println!("{}", output.to_string());

    output.into()
}

// TODO: This needs a lot of input checking and error reporting work
#[proc_macro_attribute]
pub fn vtable_override(_attr: proc_macro::TokenStream, item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let mut input = syn::parse_macro_input!(item as syn::ItemFn);
    let mut output = TokenStream::new();

    // println!("{}", input.to_token_stream().to_string());

    input.attrs.push(syn::parse_quote!(#[cfg(not(all(windows, target_arch = "x86")))]));

    input.sig.abi = syn::parse_quote!(extern "C");

    output.extend(input.to_token_stream());

    input.attrs.pop();
    input.attrs.push(syn::parse_quote!(#[cfg(all(windows, target_arch = "x86", feature = "thiscall"))]));

    input.sig.abi = syn::parse_quote!(extern "thiscall");

    output.extend(input.to_token_stream());

    input.attrs.pop();
    input.attrs.push(syn::parse_quote!(#[cfg(all(windows, target_arch = "x86", not(feature = "thiscall")))]));

    // Add a dummy argument to be passed in edx
    input.sig.inputs.insert(1, syn::parse_quote!(_dummy: *const usize));

    input.sig.abi = syn::parse_quote!(extern "fastcall");

    output.extend(input.to_token_stream());

    // println!("{}", output.to_string());

    output.into()
}

fn error(s: &str, start: Span, end: Span) -> TokenStream {
    let mut v = Vec::new();
    v.push(respan(Literal::string(&s), Span::call_site()));
    let group = v.into_iter().collect();

    let mut r = Vec::<TokenTree>::new();
    r.push(respan(Ident::new("compile_error", start), start));
    r.push(respan(Punct::new('!', Spacing::Alone), Span::call_site()));
    r.push(respan(Group::new(Delimiter::Brace, group), end));

    r.into_iter().collect()
}

fn respan<T: Into<TokenTree>>(t: T, span: Span) -> TokenTree {
    let mut t = t.into();
    t.set_span(span);
    t
}
