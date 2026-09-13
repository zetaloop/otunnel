pub mod state;

use anyhow::{Context, Result};
use serde_json::{Value, json};
use state::{AdminProfile, AdminProfiles, Root};

/// Local administrative profiles and managed tunnel processes.
#[derive(Default)]
pub struct Manager {
    pub root: Root,
}

impl Manager {
    pub fn profiles(&self) -> Result<Value> {
        let file = self.root.profiles()?;
        let profiles = file
            .profiles
            .keys()
            .map(|name| self.profile(&file, name))
            .collect::<Result<Vec<_>>>()?;
        Ok(
            json!({"profiles":profiles,"active_profile":file.active_profile,"path":self.root.path.join("admin_profiles.yaml"),"state_root":self.root.path}),
        )
    }
    pub fn set_profile(
        &self,
        name: &str,
        base: &str,
        prefix: &str,
        key: &str,
        activate: bool,
    ) -> Result<Value> {
        self.root.initialize()?;
        let name = state::alias(name)?;
        let mut file = self.root.profiles()?;
        let previous = file.profiles.get(&name).cloned().unwrap_or_default();
        let profile = AdminProfile {
            name: name.clone(),
            control_plane_base_url: first(&[
                base,
                &previous.control_plane_base_url,
                &state::variable("CONTROL_PLANE_BASE_URL").unwrap_or_default(),
                "https://api.openai.com",
            ]),
            control_plane_url_path: first(&[
                prefix,
                &previous.control_plane_url_path,
                &state::variable("CONTROL_PLANE_URL_PATH").unwrap_or_default(),
            ]),
            admin_key: first(&[key, &previous.admin_key, "env:OPENAI_ADMIN_KEY"]),
            updated_at: state::timestamp(),
        };
        state::reference(&profile.admin_key)?;
        file.profiles.insert(name.clone(), profile);
        if activate || file.active_profile.is_empty() {
            file.active_profile = name.clone();
        }
        self.root.save("admin_profiles.yaml", &file)?;
        self.profile_result(&file, &name)
    }
    pub fn activate_profile(&self, name: &str) -> Result<Value> {
        let name = state::alias(name)?;
        let mut file = self.root.profiles()?;
        anyhow::ensure!(
            file.profiles.contains_key(&name),
            "admin profile {name} is not known"
        );
        file.active_profile = name.clone();
        self.root.save("admin_profiles.yaml", &file)?;
        self.profile_result(&file, &name)
    }
    pub fn delete_profile(&self, name: &str) -> Result<Value> {
        let name = state::alias(name)?;
        let mut file = self.root.profiles()?;
        anyhow::ensure!(
            file.profiles.contains_key(&name),
            "admin profile {name} is not known"
        );
        for record in self.root.aliases()?.values() {
            anyhow::ensure!(
                record.admin_profile != name,
                "admin profile {name} is still referenced by alias {}",
                record.alias
            );
        }
        for record in self.root.processes()?.values() {
            anyhow::ensure!(
                record.admin_profile != name || record.alias.is_empty() || record.mode == "stopped",
                "admin profile {name} is still referenced by active runtime {}",
                record.alias
            );
        }
        file.profiles.remove(&name);
        if file.active_profile == name {
            file.active_profile = file.profiles.keys().next().cloned().unwrap_or_default();
        }
        self.root.save("admin_profiles.yaml", &file)?;
        Ok(
            json!({"deleted_profile":name,"active_profile":file.active_profile,"path":self.root.path.join("admin_profiles.yaml"),"state_root":self.root.path}),
        )
    }
    fn profile(&self, file: &AdminProfiles, name: &str) -> Result<Value> {
        let mut profile = serde_json::to_value(
            file.profiles
                .get(name)
                .context("admin profile is missing")?,
        )?;
        profile["path"] = json!(self.root.path.join("admin_profiles.yaml"));
        profile["active"] = json!(file.active_profile == name);
        Ok(profile)
    }
    fn profile_result(&self, file: &AdminProfiles, name: &str) -> Result<Value> {
        Ok(
            json!({"profile":self.profile(file, name)?,"active_profile":file.active_profile,"path":self.root.path.join("admin_profiles.yaml"),"state_root":self.root.path}),
        )
    }
}

fn first(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_owned()
}
