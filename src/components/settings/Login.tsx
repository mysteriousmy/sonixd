import React, { useRef, useState } from 'react';
import md5 from 'md5';
import randomstring from 'randomstring';
import settings from 'electron-settings';
import { Form, ControlLabel, Message, RadioGroup } from 'rsuite';
import axios from 'axios';
import { useTranslation } from 'react-i18next';
import setDefaultSettings from '../shared/setDefaultSettings';
import {
  StyledButton,
  StyledCheckbox,
  StyledInput,
  StyledInputPickerContainer,
  StyledRadio,
  CustomLoginLogo,
} from '../shared/styled';
import { LoginPanel } from './styled';
import GenericPage from '../layout/GenericPage';
import { mockSettings } from '../../shared/mockSettings';
import packageJson from '../../package.json';
import { Server } from '../../types';

const Login = () => {
  const { t } = useTranslation();
  const [serverType, setServerType] = useState('subsonic');
  const [serverName, setServerName] = useState(packageJson.author.url);
  const [userName, setUserName] = useState('');
  const [password, setPassword] = useState('');
  const [isLogin, setIsLogin] = useState(true);
  const [confirm_password, setConfirmPassword] = useState('');
  const [legacyAuth, setLegacyAuth] = useState(false);
  const [message, setMessage] = useState('');
  const serverTypePickerRef = useRef(null);
  const handleSignUp = async () => {
    const cleanServerName = serverName.replace(/\/$/, '');
    const salt = randomstring.generate({ length: 16, charset: 'alphanumeric' });
    const hash = md5(password + salt);
    if (cleanServerName.length === 0) {
      console.log(cleanServerName);

      setMessage('请输入服务器地址!');
      return;
    }
    if (password !== confirm_password) {
      setMessage('两次密码输入不一致！');
      return;
    }
    try {
      const signup = await axios.post(`${cleanServerName}/auth/createNormalUser`, {
        username: userName,
        password: password,
      });
      if (signup.status < 200 || signup.status > 300) {
        setMessage(signup.statusText);
        return;
      }
    } catch (err) {
      if (err instanceof Error) {
        setMessage(`${err.message}`);
        return;
      }
      setMessage(t('An unknown error occurred'));
    }
    localStorage.setItem('server', cleanServerName);
    localStorage.setItem('serverBase64', btoa(cleanServerName));
    localStorage.setItem('serverType', 'subsonic');
    localStorage.setItem('username', userName);
    localStorage.setItem('password', password);
    localStorage.setItem('salt', salt);
    localStorage.setItem('hash', hash);

    settings.setSync('server', cleanServerName);
    settings.setSync('serverBase64', btoa(cleanServerName));
    settings.setSync('serverType', 'subsonic');
    settings.setSync('username', userName);
    settings.setSync('password', password);
    settings.setSync('salt', salt);
    settings.setSync('hash', hash);

    // Set defaults on login
    setDefaultSettings(false);
    window.location.reload();
  };
  const handleConnect = async () => {
    setMessage('');
    const cleanServerName = serverName.replace(/\/$/, '');
    const salt = randomstring.generate({ length: 16, charset: 'alphanumeric' });
    const hash = md5(password + salt);

    try {
      const testConnection = legacyAuth
        ? await axios.get(
            `${cleanServerName}/rest/ping.view?v=1.13.0&c=sonixd&f=json&u=${userName}&p=${password}`
          )
        : await axios.get(
            `${cleanServerName}/rest/ping.view?v=1.13.0&c=sonixd&f=json&u=${userName}&s=${salt}&t=${hash}`
          );

      // Since a valid request will return a 200 response, we need to check that there
      // are no additional failures reported by the server
      if (testConnection.data['subsonic-response'].status === 'failed') {
        setMessage(`${testConnection.data['subsonic-response'].error.message}`);
        return;
      }
    } catch (err) {
      if (err instanceof Error) {
        setMessage(`${err.message}`);
        return;
      }
      setMessage(t('An unknown error occurred'));
      return;
    }

    localStorage.setItem('server', cleanServerName);
    localStorage.setItem('serverBase64', btoa(cleanServerName));
    localStorage.setItem('serverType', 'subsonic');
    localStorage.setItem('username', userName);
    localStorage.setItem('password', password);
    localStorage.setItem('salt', salt);
    localStorage.setItem('hash', hash);

    settings.setSync('server', cleanServerName);
    settings.setSync('serverBase64', btoa(cleanServerName));
    settings.setSync('serverType', 'subsonic');
    settings.setSync('username', userName);
    settings.setSync('password', password);
    settings.setSync('salt', salt);
    settings.setSync('hash', hash);

    // Set defaults on login
    setDefaultSettings(false);
    window.location.reload();
  };
  const handleConnectJellyfin = async () => {
    setMessage('');
    const cleanServerName = serverName.replace(/\/$/, '');
    const deviceId = randomstring.generate({ length: 12, charset: 'alphanumeric' });

    try {
      const { data } = await axios.post(
        `${cleanServerName}/users/authenticatebyname`,
        {
          Username: userName,
          Pw: password,
        },
        {
          headers: {
            'X-Emby-Authorization': `MediaBrowser Client="Sonixd", Device="PC", DeviceId="${deviceId}", Version="${packageJson.version}"`,
          },
        }
      );

      localStorage.setItem('server', cleanServerName);
      localStorage.setItem('serverBase64', btoa(cleanServerName));
      localStorage.setItem('serverType', 'jellyfin');
      localStorage.setItem('username', data.User.Id);
      localStorage.setItem('token', data.AccessToken);
      localStorage.setItem('deviceId', deviceId);

      settings.setSync('server', cleanServerName);
      settings.setSync('serverBase64', btoa(cleanServerName));
      settings.setSync('serverType', 'jellyfin');
      settings.setSync('username', data.User.Id);
      settings.setSync('token', data.AccessToken);
      settings.setSync('deviceId', deviceId);
    } catch (err) {
      if (err instanceof Error) {
        setMessage(`${err.message}`);
        return;
      }
      setMessage(t('An unknown error occurred'));
      return;
    }

    // Set defaults on login
    setDefaultSettings(false);
    window.location.reload();
  };

  return (
    <GenericPage hideDivider>
      <LoginPanel bordered style={{ display: isLogin ? 'block' : 'none' }}>
        <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <CustomLoginLogo />
        </span>
        <br />
        {message !== '' && <Message type="error" description={message} />}
        <Form id="login-form" fluid style={{ paddingTop: '10px' }}>
          <StyledInputPickerContainer ref={serverTypePickerRef} style={{ display: 'none' }}>
            <ControlLabel>{t('Server type')}</ControlLabel>
            <RadioGroup
              inline
              defaultValue="subsonic"
              value={serverType}
              onChange={(e: Server) => setServerType(e)}
            >
              <StyledRadio value="subsonic">Subsonic</StyledRadio>
              <StyledRadio value="jellyfin">Jellyfin</StyledRadio>
            </RadioGroup>
          </StyledInputPickerContainer>
          <ControlLabel style={{ display: 'none' }}>{t('Server')}</ControlLabel>
          <StyledInput
            id="login-servername"
            name="servername"
            value={serverName}
            style={{ display: 'none' }}
            onChange={(e: string) => setServerName(e)}
            placeholder={t('Requires http(s)://')}
          />
          <ControlLabel>{t('Username')}</ControlLabel>
          <StyledInput
            id="login-username"
            name="name"
            value={userName}
            onChange={(e: string) => setUserName(e)}
            placeholder={t('Enter username')}
          />
          <br />
          <ControlLabel>{t('Password')}</ControlLabel>
          <StyledInput
            id="login-password"
            name="password"
            type="password"
            value={password}
            onChange={(e: string) => setPassword(e)}
            placeholder={t('Enter password')}
          />
          <br />
          {serverType !== 'jellyfin' && (
            <>
              <StyledCheckbox
                defaultChecked={
                  process.env.NODE_ENV === 'test'
                    ? mockSettings.legacyAuth
                    : Boolean(settings.getSync('legacyAuth'))
                }
                checked={legacyAuth}
                onChange={(_v: any, e: boolean) => {
                  settings.setSync('legacyAuth', e);
                  setLegacyAuth(e);
                }}
              >
                {t('Legacy auth (plaintext)')}
              </StyledCheckbox>
              <br />
            </>
          )}
          <StyledButton
            id="login-button"
            appearance="primary"
            type="submit"
            block
            onClick={serverType !== 'jellyfin' ? handleConnect : handleConnectJellyfin}
          >
            {t('Connect')}
          </StyledButton>
          <StyledButton
            id="sign-button"
            appearance="primary"
            type="submit"
            block
            onClick={() => setIsLogin(false)}
          >
            {t('注册账户')}
          </StyledButton>
        </Form>
      </LoginPanel>
      <LoginPanel bordered style={{ display: isLogin ? 'none' : 'block' }}>
        <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <CustomLoginLogo />
        </span>
        <br />
        {message !== '' && <Message type="error" description={message} />}
        <Form id="login-form" fluid style={{ paddingTop: '10px' }}>
          <StyledInputPickerContainer ref={serverTypePickerRef} style={{ display: 'none' }}>
            <ControlLabel>{t('Server type')}</ControlLabel>
            <RadioGroup
              inline
              defaultValue="subsonic"
              value={serverType}
              onChange={(e: Server) => setServerType(e)}
            >
              <StyledRadio value="subsonic">Subsonic</StyledRadio>
              <StyledRadio value="jellyfin">Jellyfin</StyledRadio>
            </RadioGroup>
          </StyledInputPickerContainer>
          <ControlLabel style={{ display: 'none' }}>{t('Server')}</ControlLabel>
          <StyledInput
            id="login-servername"
            name="servername"
            style={{ display: 'none' }}
            value={serverName}
            onChange={(e: string) => setServerName(e)}
            placeholder={t('Requires http(s)://')}
          />
          <ControlLabel>{t('Username')}</ControlLabel>
          <StyledInput
            id="login-username"
            name="name"
            value={userName}
            onChange={(e: string) => setUserName(e)}
            placeholder={t('Enter username')}
          />
          <br />
          <ControlLabel>{t('Password')}</ControlLabel>
          <StyledInput
            id="login-password"
            name="password"
            type="password"
            value={password}
            onChange={(e: string) => setPassword(e)}
            placeholder={t('Enter password')}
          />
          <br />
          <ControlLabel>{t('Password')}</ControlLabel>
          <StyledInput
            id="login-password"
            name="confirm-password"
            type="password"
            value={confirm_password}
            onChange={(e: string) => setConfirmPassword(e)}
            placeholder={t('Confirm Enter password')}
          />
          <br />
          <StyledButton
            id="login-button"
            appearance="primary"
            type="submit"
            block
            onClick={handleSignUp}
          >
            {t('Sign Up')}
          </StyledButton>
          <StyledButton
            id="lo-button"
            appearance="primary"
            type="submit"
            block
            onClick={() => setIsLogin(true)}
          >
            {t('登陆账户')}
          </StyledButton>
        </Form>
      </LoginPanel>
    </GenericPage>
  );
};

export default Login;
