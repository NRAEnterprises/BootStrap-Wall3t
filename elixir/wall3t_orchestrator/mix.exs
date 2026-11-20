defmodule Wall3tOrchestrator.MixProject do
  use Mix.Project

  def project do
    [
      app: :wall3t_orchestrator,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: []
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {Wall3t.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
