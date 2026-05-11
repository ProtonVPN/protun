// Copyright (c) 2026 Proton AG
//
// This file is part of ProtonVPN.
//
// ProtonVPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ProtonVPN is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.

use std::future::Future;
use std::pin::Pin;

use async_compat::Compat;
use futures::TryFutureExt as _;
use muon::App;
use muon::auth::LoginFlow;
use muon::rt::{
    Monotonic, MuonSystemTime, OperatingSystem, Resolve, SinceUnixEpoch as _, SystemTimeFactory,
    TcpConnect,
};

#[derive(Debug, Clone)]
pub struct TimeCapability {
    at_start: std::time::Instant,
}

impl Default for TimeCapability {
    fn default() -> Self {
        Self {
            at_start: std::time::Instant::now(),
        }
    }
}

impl muon::rt::Sleep for TimeCapability {
    type Sleep<'a>
        = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>>
    where
        Self: 'a;

    fn sleep(&self, duration: std::time::Duration) -> Self::Sleep<'static> {
        Box::pin(tokio::time::sleep(duration))
    }
}

impl muon::rt::InstantFactory for TimeCapability {
    type Instant = muon::rt::MuonInstant;

    fn now(&self) -> Self::Instant {
        muon::rt::MuonInstant::from_duration(std::time::Instant::now() - self.at_start)
    }
}

unsafe impl Monotonic for TimeCapability {}

impl SystemTimeFactory for TimeCapability {
    type SystemTime = MuonSystemTime;

    fn now(&self) -> Self::SystemTime {
        MuonSystemTime::since_unix_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("failed to get time"),
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct MyTcpConnector;

impl TcpConnect for MyTcpConnector {
    type Socket = Compat<tokio::net::TcpStream>;
    type Err = std::io::Error;

    fn tcp_connect(
        &self,
        addr: std::net::SocketAddr,
    ) -> impl Future<Output = Result<Self::Socket, Self::Err>> {
        tokio::net::TcpStream::connect(addr).map_ok(Compat::new)
    }
}

#[derive(Debug, Clone, Default)]
pub struct MyResolver;

impl Resolve for MyResolver {
    fn resolve(
        &self,
        host: &str,
    ) -> impl std::future::Future<Output = std::result::Result<Vec<std::net::IpAddr>, Self::Err>>
    {
        tokio::net::lookup_host(format!("{host}:80"))
            .map_ok(|addresses| addresses.map(|addr| addr.ip()).collect())
    }

    type Err = std::io::Error;
}

#[derive(Debug, Clone, Default)]
pub struct MyOperatingSystem {
    time: TimeCapability,
    dialer: MyTcpConnector,
    resolver: MyResolver,
}

impl OperatingSystem for MyOperatingSystem {
    type Resolver = MyResolver;
    type TcpConnector = MyTcpConnector;
    type Time = TimeCapability;

    fn get_time_capabilities(&self) -> &Self::Time {
        &self.time
    }

    fn get_tcp_connector(&self) -> &Self::TcpConnector {
        &self.dialer
    }

    fn get_resolver(&self) -> &Self::Resolver {
        &self.resolver
    }
}

#[derive(Debug, Clone)]
pub struct TokioExecutor;

impl muon::rt::Spawn for TokioExecutor {
    fn spawn_obj(
        &self,
        future: muon::rt::FutureObj<'static, ()>,
    ) -> Result<(), muon::rt::SpawnError> {
        let _ = tokio::spawn(future);
        Ok(())
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn get_session_fork_selector(app: &str, user: &str, pass: &str) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(get_session_fork_selector_async(app, user, pass))
}

pub async fn get_session_fork_selector_async(app: &str, user: &str, pass: &str) -> String {
    let app = App::new(app).expect("valid app version");
    let env = muon::Environment::new_prod();
    let session = muon::Client::builder(app.clone(), env)
        .with_operating_system(MyOperatingSystem::default(), rand::rng())
        .with_multi_thread_executor(TokioExecutor)
        .without_persistence::<()>()
        .build()
        .unwrap()
        .new_session_without_credentials(())
        .await
        .unwrap();

    let session = match session
        .auth()
        .login(user, pass)
        .await
    {
        LoginFlow::Ok(session, _) => session,
        LoginFlow::TwoFactor(_, _) => panic!("unexpected 2FA"),
        LoginFlow::Failed { reason, .. } => panic!("failed to auth {reason:?}"),
    };

    pvpnclient::util::fork_muon_session(session, app)
        .await
        .unwrap()
}
