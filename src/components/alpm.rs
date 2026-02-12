use std::{collections::HashMap, io::Read, str::FromStr};

use alpm_db::desc::DbDescFile;
use alpm_mtree::mtree::v2::Path;
use anyhow::{Context, Result, anyhow};
use camino::{Utf8Path, Utf8PathBuf};
use indexmap::IndexMap;
use ocidir::cap_std::fs::Dir;

use crate::components::{ComponentId, ComponentInfo, ComponentsRepo, FileMap, FileType};

const REPO_NAME: &str = "alpm";
const LOCALDB_PATHS: &[&str] = &["usr/lib/sysimage/lib/pacman/local", "var/lib/pacman/local"];

const DESC_FILENAME: &str = "desc";
const MTREE_FILENAME: &str = "mtree";

const GZIP_MAGIC: &[u8] = &[0x1F, 0x8B];

pub struct AlpmComponentsRepo {
    /// Unique component (BASE) names mapped to buildtime, indexed by ComponentId.
    components: IndexMap<String, u64>,

    /// Mapping from path to list of ComponentId.
    ///
    /// It's common for directories to be owned by more than one component (i.e.
    /// from _different_ packages).
    path_to_components: HashMap<Utf8PathBuf, Vec<(ComponentId, FileType)>>,
}

impl AlpmComponentsRepo {
    pub fn load(rootfs: &Dir, files: &FileMap) -> Result<Option<Self>> {
        let local_db = match Self::try_open_local_db(rootfs) {
            Some(dir) => dir,
            None => return Ok(None),
        };
        Self::load_from_db(&local_db, files).map(Some)
    }

    fn try_open_local_db(rootfs: &Dir) -> Option<Dir> {
        for local_db_path in LOCALDB_PATHS {
            if let Ok(dir) = rootfs.open_dir(*local_db_path) {
                return Some(dir);
            }
        }
        None
    }

    /// Starting from the `local_db` base directory, iterate over the packages in the local database,
    /// process package metadata and generate an index of components and their files.
    pub fn load_from_db(local_db: &Dir, files: &FileMap) -> Result<Self> {
        let mut components = IndexMap::new();
        let mut path_to_components = HashMap::new();

        // The local package database is basically a directory that contains
        // one directory for each locally installed package. Inside this directory,
        // there are metadata files:
        // `desc`: package metadata
        // `files`: file list
        // `mtree` files and file metadata such as owner, link target, hash value (possibly compressed)
        // Example:
        //  $ ls /var/lib/pacman/local/just-1.46.0-1
        //  desc  files  mtree
        for local_db_entry in local_db.entries()? {
            let local_db_entry = local_db_entry?;
            if local_db_entry.file_type()?.is_dir() {
                let package_dir = local_db_entry.open_dir()?;
                let (desc, mtree) =
                    Self::package_info_from_dir(&package_dir).with_context(|| {
                        format!(
                            "parsing metadata of package {:?}",
                            local_db_entry.file_name()
                        )
                    })?;
                let (basename, build_date) = match desc {
                    DbDescFile::V1(desc) => (
                        desc.base.to_string(),
                        u64::try_from(desc.builddate).expect("no dates before 1970"),
                    ),
                    DbDescFile::V2(desc) => (
                        desc.base.to_string(),
                        u64::try_from(desc.builddate).expect("no dates before 1970"),
                    ),
                };
                let (component_id, _) = components.insert_full(basename, build_date);
                Self::mtree_to_map(
                    &mut path_to_components,
                    ComponentId(component_id),
                    &mtree,
                    files,
                )?;
            }
        }
        Ok(Self {
            components,
            path_to_components,
        })
    }

    fn package_info_from_dir(
        package_dir: &Dir,
    ) -> Result<(DbDescFile, Vec<alpm_mtree::mtree::v2::Path>)> {
        let desc = {
            let mut file = package_dir.open(DESC_FILENAME)?.into_std();
            let mut content = String::new();
            file.read_to_string(&mut content)
                .context("read desc file")?;
            alpm_db::desc::DbDescFile::from_str(&content).context("parse desc")?
        };
        let mtree = {
            // mtree files might be compressed, so we read it into a Vec<u8> first
            // and decompress that if needed
            let mut file = package_dir.open(MTREE_FILENAME)?.into_std();
            let mut content = Vec::new();
            file.read_to_end(&mut content).context("read mtree file")?;

            // Does it look like it is gzip-compressed?
            if content.starts_with(GZIP_MAGIC) {
                let mut decompressed = Vec::new();
                flate2::read::GzDecoder::new(content.as_slice())
                    .read_to_end(&mut decompressed)
                    .context("decompressing mtree")?;
                content = decompressed;
            }

            // Now hope that we have a valid mtree file and decode it into a String
            let content = String::from_utf8(content).context("decode mtree to utf-8")?;
            alpm_mtree::parse_mtree_v2(content).context("parse mtree")?
        };
        Ok((desc, mtree))
    }

    fn mtree_to_map(
        path_to_components: &mut HashMap<Utf8PathBuf, Vec<(ComponentId, FileType)>>,
        component_id: ComponentId,
        mtree: &Vec<Path>,
        // TODO: Use this for path canonicalization
        _files: &FileMap,
    ) -> Result<()> {
        for path in mtree {
            let file_type = match path {
                Path::Directory(_) => FileType::Directory,
                Path::File(_) => FileType::File,
                Path::Link(_) => FileType::Symlink,
            };
            // The mtree contains paths of the form "./usr/bin/sh",
            // as_normalized_path strips their prefix such that we get relative paths like "usr/bin/sh"
            // Canonicalization wants absolute paths
            // SAFETY: "/" is always a valid path
            let mut absolute_path = Utf8PathBuf::from_str("/").unwrap();
            let normalized_path = path.as_normalized_path().context("normalize mtree path")?;
            let relative_path = Utf8Path::from_path(normalized_path)
                .ok_or_else(|| anyhow!("package database contains non-utf8 path"))?;
            absolute_path.push(relative_path);
            path_to_components
                .entry(absolute_path)
                .or_default()
                .push((component_id, file_type));
        }
        Ok(())
    }
}

impl ComponentsRepo for AlpmComponentsRepo {
    fn name(&self) -> &'static str {
        REPO_NAME
    }

    fn default_priority(&self) -> usize {
        10
    }

    fn claims_for_path(&self, path: &Utf8Path, file_type: FileType) -> Vec<ComponentId> {
        self.path_to_components
            .get(path)
            .map(|components| {
                components
                    .iter()
                    .filter_map(|(id, ftype)| if ftype == &file_type { Some(*id) } else { None })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn component_info(&self, id: ComponentId) -> ComponentInfo<'_> {
        // Safety: We handed out the ComponentId by ourselves and obtained it directly from the `IndexMap`
        let (pkgbase, build_time) = self.components.get_index(id.0).unwrap();
        ComponentInfo {
            name: pkgbase.as_str(),
            mtime_clamp: *build_time,
            stability: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::Path};

    use camino::Utf8Path;
    use ocidir::cap_std::{ambient_authority, fs::Dir};

    use crate::components::{ComponentsRepo, FileType, alpm::AlpmComponentsRepo};

    fn rootfs() -> Dir {
        let rootfs = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("arch-rootfs");
        Dir::open_ambient_dir(&rootfs, ambient_authority()).unwrap()
    }

    #[test]
    fn claims_correct_files() {
        let files = BTreeMap::new();
        let alpm = AlpmComponentsRepo::load(&rootfs(), &files)
            .unwrap()
            .unwrap();
        let claims = alpm.claims_for_path(Utf8Path::new("/usr"), FileType::Directory);
        assert_eq!(claims.len(), 2);
        let claims = alpm.claims_for_path(Utf8Path::new("/usr"), FileType::File);
        assert!(claims.is_empty());
        let claims = alpm.claims_for_path(Utf8Path::new("/usr"), FileType::Symlink);
        assert!(claims.is_empty());
    }
}
