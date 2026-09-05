import { afterAll, beforeEach, describe, expect, it } from 'bun:test';
import {
  buildHostedLogoutUrl,
  buildHostedBrandingCss,
  buildSupabaseAuthUiConfig,
  mapConnectorsToSupabaseProviders,
  resolveSupabaseAuthUiConfig,
} from '../index.js';

describe('buildHostedLogoutUrl', () => {
  it('builds the central hosted logout URL with RP logout context', () => {
    expect(buildHostedLogoutUrl({
      supauthUrl: 'https://auth.example.test/auth/v1',
      clientId: 'business-app',
      idTokenHint: 'header.payload.signature',
      postLogoutRedirectUri: 'https://app.example.test/login',
      state: 'signed-out',
    })).toBe('https://auth.example.test/logout?client_id=business-app&id_token_hint=header.payload.signature&post_logout_redirect_uri=https%3A%2F%2Fapp.example.test%2Flogin&state=signed-out');
  });

  it('rejects partial redirect validation context', () => {
    expect(() => buildHostedLogoutUrl({
      supauthUrl: 'https://auth.example.test',
      postLogoutRedirectUri: 'https://app.example.test/login',
    })).toThrow('must be provided together');
  });
});

describe('sdk-auth-ui bridge helpers', () => {
  const baseExperience = {
    branding: {
      primary_color: '#123456',
      page_title: 'Acme Login',
      background_url: 'https://cdn.example.com/bg.png',
      custom_css: '.hero { display: none; }',
    },
    sign_in_methods: ['password'],
    sign_up_enabled: true,
    password_policy: {
      min_length: 8,
      require_uppercase: false,
      require_lowercase: false,
      require_numbers: false,
      require_symbols: false,
    },
    connectors: [
      { id: 'google', name: 'Google', type: 'social' },
      { id: 'oidc-acme', name: 'Acme SSO', type: 'enterprise_sso' },
    ],
  };

  it('maps only supported connectors to Supabase auth-ui providers', () => {
    const result = mapConnectorsToSupabaseProviders(baseExperience.connectors);
    expect(result.supportedProviders).toEqual(['google']);
    expect(result.unsupportedConnectors).toHaveLength(1);
    expect(result.unsupportedConnectors[0]?.id).toBe('oidc-acme');
  });

  it('builds auth-ui props from experience and phrases', () => {
    const config = buildSupabaseAuthUiConfig({
      experience: baseExperience,
      phrases: {
        email: '邮箱',
        password: '密码',
        sign_up: {
          button_label: '创建账号',
        },
      },
      view: 'sign_up',
      redirectTo: 'https://app.example.com/callback',
    });

    expect(config.auth.providers).toEqual(['google']);
    expect(config.auth.view).toBe('sign_up');
    expect(config.auth.redirectTo).toBe('https://app.example.com/callback');
    expect(config.auth.appearance.variables.default.colors.brand).toBe('#123456');
    expect(config.auth.localization.variables.sign_in?.email_label).toBe('邮箱');
    expect(config.auth.localization.variables.sign_up?.button_label).toBe('创建账号');
  });

  it('renders hosted branding css from background and custom css', () => {
    const css = buildHostedBrandingCss({
      backgroundUrl: 'https://cdn.example.com/bg.png',
      customCss: '.card { border-radius: 20px; }',
    });
    expect(css).toContain('background-image');
    expect(css).toContain('.card { border-radius: 20px; }');
  });

  it('ignores unsafe background URLs without allowing CSS boundary injection', () => {
    expect(buildHostedBrandingCss({
      backgroundUrl: 'javascript:alert(1)',
    })).toBe('');
    expect(buildHostedBrandingCss({
      backgroundUrl: 'https://cdn.example.com/" ); color: red; /*',
    })).not.toContain('color: red');
    expect(buildHostedBrandingCss({
      backgroundUrl: 'https://user:pass@cdn.example.com/bg.png',
    })).toBe('');
  });
});

describe('resolveSupabaseAuthUiConfig', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/v1/public/sign-in-experience/resolve?application_id=app-1')) {
        return new Response(JSON.stringify({
          branding: { primary_color: '#2563eb' },
          sign_in_methods: ['password'],
          sign_up_enabled: true,
          password_policy: {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_numbers: false,
            require_symbols: false,
          },
          connectors: [{ id: 'github', name: 'GitHub', type: 'social' }],
        }), { status: 200 });
      }
      if (url.endsWith('/v1/public/phrases/zh-CN')) {
        return new Response(JSON.stringify({
          language_tag: 'zh-CN',
          phrases: { email: '邮箱' },
        }), { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }) as typeof fetch;
  });

  it('resolves public experience and phrases through the shared client', async () => {
    const config = await resolveSupabaseAuthUiConfig({
      baseUrl: 'https://auth.example.com',
      applicationId: 'app-1',
      locale: 'zh-CN',
    });

    expect(config.auth.providers).toEqual(['github']);
    expect(config.auth.localization.variables.sign_in?.email_label).toBe('邮箱');
    expect(config.auth.appearance.variables.default.colors.brand).toBe('#2563eb');
  });

  afterAll(() => {
    globalThis.fetch = originalFetch;
  });
});
