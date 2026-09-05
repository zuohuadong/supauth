import { SupaOAuthClient } from '@supauth/sdk-typescript';
import type {
  PublicEffectiveSignInExperience,
  PublicPhraseBundle,
  PublicSignInConnector,
} from '@supauth/shared';

const SUPABASE_PROVIDER_IDS = [
  'apple',
  'azure',
  'bitbucket',
  'discord',
  'facebook',
  'github',
  'gitlab',
  'google',
  'keycloak',
  'linkedin',
  'notion',
  'spotify',
  'slack',
  'twitch',
  'twitter',
  'workos',
  'zoom',
  'email',
  'phone',
  'saml',
] as const;

const CREDENTIAL_METHOD_IDS = new Set([
  'password',
  'email',
  'email_password',
  'phone',
  'phone_password',
]);

export type SupabaseAuthUiProvider = typeof SUPABASE_PROVIDER_IDS[number];
export type EmbeddedAuthUiView = 'sign_in' | 'sign_up' | 'forgotten_password';

export interface HostedBranding {
  pageTitle?: string;
  logoUrl?: string;
  faviconUrl?: string;
  backgroundUrl?: string;
  primaryColor?: string;
  buttonLabel?: string;
  customCss?: string;
}

export interface AuthUiLocalizationVariables {
  sign_in?: Record<string, string>;
  sign_up?: Record<string, string>;
  forgotten_password?: Record<string, string>;
}

export interface SupabaseAuthUiBridgeConfig {
  auth: {
    providers: SupabaseAuthUiProvider[];
    view: EmbeddedAuthUiView;
    theme: 'default';
    showLinks: boolean;
    onlyThirdPartyProviders: boolean;
    redirectTo?: string;
    appearance: {
      extend: true;
      variables: {
        default: {
          colors: Record<string, string>;
          fonts: Record<string, string>;
          radii: Record<string, string>;
        };
      };
    };
    localization: {
      variables: AuthUiLocalizationVariables;
    };
  };
  brand: HostedBranding;
  unsupportedConnectors: PublicSignInConnector[];
  experience: PublicEffectiveSignInExperience;
}

export interface ResolveSupabaseAuthUiConfigOptions {
  baseUrl: string;
  applicationId?: string;
  authorizationId?: string;
  locale?: string;
  view?: EmbeddedAuthUiView;
  redirectTo?: string;
}

export interface HostedLogoutUrlOptions {
  supauthUrl: string;
  clientId?: string;
  idTokenHint?: string;
  postLogoutRedirectUri?: string;
  state?: string;
}

export function buildHostedLogoutUrl(options: HostedLogoutUrlOptions): string {
  const endpoint = new URL('/logout', options.supauthUrl);
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password) {
    throw new TypeError('supauthUrl must be an http(s) URL without credentials');
  }
  const redirectFields = [options.clientId, options.idTokenHint, options.postLogoutRedirectUri];
  const configuredRedirectFields = redirectFields.filter(Boolean).length;
  if (configuredRedirectFields > 0 && configuredRedirectFields !== redirectFields.length) {
    throw new TypeError('clientId, idTokenHint, and postLogoutRedirectUri must be provided together');
  }
  if (options.clientId) endpoint.searchParams.set('client_id', options.clientId);
  if (options.idTokenHint) endpoint.searchParams.set('id_token_hint', options.idTokenHint);
  if (options.postLogoutRedirectUri) endpoint.searchParams.set('post_logout_redirect_uri', options.postLogoutRedirectUri);
  if (options.state) endpoint.searchParams.set('state', options.state);
  return endpoint.toString();
}

function compactStrings(values: Record<string, string | undefined>) {
  return Object.fromEntries(
    Object.entries(values).filter(([, value]) => typeof value === 'string' && value.trim()),
  ) as Record<string, string>;
}

function getPhraseValue(
  phrases: Record<string, unknown>,
  dottedKey: string,
  fallbackKey?: string,
): string | undefined {
  const direct = phrases[dottedKey];
  if (typeof direct === 'string' && direct.trim()) return direct;

  const segments = dottedKey.split('.');
  let current: unknown = phrases;
  for (const segment of segments) {
    if (!current || typeof current !== 'object') {
      current = undefined;
      break;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  if (typeof current === 'string' && current.trim()) return current;

  if (fallbackKey) {
    const fallback = phrases[fallbackKey];
    if (typeof fallback === 'string' && fallback.trim()) return fallback;
  }
  return undefined;
}

function toBranding(experience: PublicEffectiveSignInExperience): HostedBranding {
  return {
    pageTitle: experience.branding.page_title,
    logoUrl: experience.branding.logo_url,
    faviconUrl: experience.branding.favicon_url,
    backgroundUrl: experience.branding.background_url,
    primaryColor: experience.branding.primary_color,
    buttonLabel: experience.branding.button_label,
    customCss: experience.branding.custom_css,
  };
}

export function mapConnectorsToSupabaseProviders(connectors: PublicSignInConnector[] = []) {
  const supportedProviders: SupabaseAuthUiProvider[] = [];
  const unsupportedConnectors: PublicSignInConnector[] = [];
  const supportedSet = new Set<string>(SUPABASE_PROVIDER_IDS);

  for (const connector of connectors) {
    if (supportedSet.has(connector.id)) {
      supportedProviders.push(connector.id as SupabaseAuthUiProvider);
    } else {
      unsupportedConnectors.push(connector);
    }
  }

  return { supportedProviders, unsupportedConnectors };
}

export function buildHostedBrandingCss(branding: HostedBranding) {
  const css: string[] = [];
  if (branding.backgroundUrl) {
    try {
      const backgroundUrl = new URL(branding.backgroundUrl);
      if (['http:', 'https:'].includes(backgroundUrl.protocol)
        && !backgroundUrl.username && !backgroundUrl.password && !backgroundUrl.hash) {
        const escapedUrl = backgroundUrl.toString()
          .replace(/\\/g, '\\\\')
          .replace(/"/g, '\\"')
          .replace(/[\r\n\f]/g, '\\A ');
        css.push(`body { background-image: url("${escapedUrl}"); background-size: cover; background-position: center; }`);
      }
    } catch {
      // Invalid branding URLs are ignored; custom CSS remains an explicit capability.
    }
  }
  if (branding.customCss) {
    css.push(branding.customCss);
  }
  return css.join('\n');
}

export function buildSupabaseAuthUiConfig(input: {
  experience: PublicEffectiveSignInExperience;
  phrases?: PublicPhraseBundle['phrases'];
  view?: EmbeddedAuthUiView;
  redirectTo?: string;
}) : SupabaseAuthUiBridgeConfig {
  const { experience, view = 'sign_in', redirectTo } = input;
  const phrases = input.phrases ?? {};
  const { supportedProviders, unsupportedConnectors } = mapConnectorsToSupabaseProviders(experience.connectors ?? []);
  const branding = toBranding(experience);
  const hasCredentialMethods = experience.sign_in_methods.length === 0
    || experience.sign_in_methods.some((method) => CREDENTIAL_METHOD_IDS.has(method));
  const hasProviders = supportedProviders.length > 0;

  return {
    auth: {
      providers: supportedProviders,
      view,
      theme: 'default',
      showLinks: true,
      onlyThirdPartyProviders: hasProviders && !hasCredentialMethods,
      redirectTo,
      appearance: {
        extend: true,
        variables: {
          default: {
            colors: {
              brand: branding.primaryColor ?? '#2563eb',
              brandAccent: branding.primaryColor ?? '#2563eb',
              brandButtonText: '#ffffff',
              inputBorderFocus: branding.primaryColor ?? '#2563eb',
            },
            fonts: {
              bodyFontFamily: '"Segoe UI", system-ui, sans-serif',
              buttonFontFamily: '"Segoe UI", system-ui, sans-serif',
              inputFontFamily: '"Segoe UI", system-ui, sans-serif',
              labelFontFamily: '"Segoe UI", system-ui, sans-serif',
            },
            radii: {
              borderRadiusButton: '10px',
              buttonBorderRadius: '10px',
              inputBorderRadius: '10px',
            },
          },
        },
      },
      localization: {
        variables: {
          sign_in: compactStrings({
            email_label: getPhraseValue(phrases, 'sign_in.email_label', 'email'),
            password_label: getPhraseValue(phrases, 'sign_in.password_label', 'password'),
            button_label: branding.buttonLabel || getPhraseValue(phrases, 'sign_in.button_label', 'submit'),
            social_provider_text: getPhraseValue(phrases, 'sign_in.social_provider_text'),
            link_text: getPhraseValue(phrases, 'sign_in.link_text', 'forgotLink'),
          }),
          sign_up: compactStrings({
            email_label: getPhraseValue(phrases, 'sign_up.email_label', 'email'),
            password_label: getPhraseValue(phrases, 'sign_up.password_label', 'password'),
            button_label: getPhraseValue(phrases, 'sign_up.button_label', 'signUpSubmit'),
            confirmation_text: getPhraseValue(phrases, 'sign_up.confirmation_text', 'signUpSuccess'),
          }),
          forgotten_password: compactStrings({
            email_label: getPhraseValue(phrases, 'forgotten_password.email_label', 'forgotEmailLabel'),
            button_label: getPhraseValue(phrases, 'forgotten_password.button_label', 'forgotSubmit'),
            confirmation_text: getPhraseValue(phrases, 'forgotten_password.confirmation_text', 'forgotSuccess'),
          }),
        },
      },
    },
    brand: branding,
    unsupportedConnectors,
    experience,
  };
}

export async function resolveSupabaseAuthUiConfig(
  options: ResolveSupabaseAuthUiConfigOptions,
): Promise<SupabaseAuthUiBridgeConfig> {
  const client = new SupaOAuthClient({ baseUrl: options.baseUrl });
  const [experience, phraseBundle] = await Promise.all([
    client.resolvePublicSignInExperience({
      application_id: options.applicationId,
      authorization_id: options.authorizationId,
    }),
    options.locale ? client.getPublicPhrases(options.locale).catch(() => null) : Promise.resolve(null),
  ]);

  return buildSupabaseAuthUiConfig({
    experience,
    phrases: phraseBundle?.phrases,
    view: options.view,
    redirectTo: options.redirectTo,
  });
}
