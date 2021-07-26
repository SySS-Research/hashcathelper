def main(argv=None):
    from .args import parse_args
    from .log import init_logging
    args = parse_args(argv=argv)
    init_logging()
    args.func(args)


if __name__ == "__main__":
    main()
