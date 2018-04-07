defmodule BtcTool.Mixfile do
  use Mix.Project

  @github_url "https://github.com/ihinojal/btctool"

  def project do
    [
      app: :btctool,
      version: "0.1.0", # Major: Incompatible API changes
                        # Minor: Backward-compatible added functionality
                        # Patch: Backward-compatible bug fixes
      elixir: "~> 1.5",
      start_permanent: Mix.env == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      source_url: @github_url,
      docs: docs()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:area58check, "~> 0.1"},
      {:dialyxir, "~> 0.5", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.16", only: :dev, runtime: false},
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"},
    ]
  end

  defp description do
    "Bitcoin utils related to Elliptic curve cryptography (ECC) algorithms "<>
    "used in bitcoin to create addresses or public keys from private keys, "<>
    "brainwallets, WIFs, etc."
  end

  defp package do
    [
      maintainers: ["Ivan H."],
      licenses: ["MIT"],
      links: %{"Github" => @github_url}
    ]
  end

  defp docs do
    [
      main: "BtcTool",
      # source_ref: "v#{@version}",
      # logo: "path/to/logo.png",
      extras: ["README.md"]
    ]
  end

end
