{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nixit = {
      url = "github:serephus/nixit";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      nixit,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
    {
      githubRepositories.pipet = nixit.lib.githubRepository {
        owner = "serephus";
        name = "pipet";

        description = "description";
        homepage = "homepage";
        topics = [
          "python"
          "pipet"
        ];
        visibility = "public";

        features = {
          wiki.enable = false;
          issues.enable = true;
          projects.enable = false;
          discussions.enable = false;
        };

        is_template = false;
        is_archived = false;

        pull = {
          merge.enable = true;
          squash.enable = false;
          rebase.enable = false;
          auto_merge = true;
          delete_branch_on_merge = true;
          update_branch = true;
        };

        actions = {
          enable = true;
          policy = "all";
          default_token_permissions = "read";
          allow_pr_approval = false;
        };

        rulesets = {
          default = {
            enforcement = "active";
            conditions.ref_name.include = [ "~DEFAULT_BRANCH" ];
            rules = [
              { type = "deletion"; }
              { type = "non_fast_forward"; }
            ];
          };
        };
      };
    }
    // flake-utils.lib.eachSystem systems (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        python' = pkgs.python3.withPackages (p: [
          p.requests
        ]);
      in
      {
        devShell = pkgs.mkShell {
          name = "pipet";
          buildInputs = [
            python'
            pkgs.curl
            pkgs.basedpyright
            pkgs.black
            pkgs.ruff
            pkgs.uv
          ];

          # Force uv to use the Python interpreter provided by Nix
          UV_PYTHON_DOWNLOADS = "never";
          UV_PYTHON = nixpkgs.lib.getExe python';
        };
      }
    );
}
